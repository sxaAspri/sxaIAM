"""
tests/integration/test_full_analysis.py

Test de integración — Fase 3 validación completa.

Simula el flujo end-to-end del análisis:
  IAMSnapshot → PolicyResolver → AttackGraph → PathFinder → EscalationPaths

El snapshot replica las 5 identidades vulnerables del sandbox Terraform:
  path1: low_priv_user      con iam:CreatePolicyVersion      → CRÍTICO
  path2: developer_user     con iam:PassRole + Lambda         → ALTO
  path3: ci_role            con sts:AssumeRole chain          → ALTO
  path4: readonly_user      con iam:AttachUserPolicy          → CRÍTICO
  path5: support_user       con iam:CreateAccessKey           → ALTO

Criterios de éxito (3q + 3r del tracker):
  ✅ 5/5 rutas detectadas
  ✅ Cada ruta tiene al menos un step con evidencia explícita
  ✅ Cada step de evidencia referencia el permiso concreto que lo justifica
  ✅ Las rutas CRÍTICAS aparecen antes que las ALTAS en el output

No usa moto ni credenciales AWS — el snapshot se construye a mano
replicando exactamente lo que get_account_authorization_details
devolvería en el sandbox Terraform.
"""

from __future__ import annotations

import pytest

from sxaiam.findings.technique_base import Severity
from sxaiam.graph.builder import AttackGraph
from sxaiam.graph.pathfinder import PathFinder
from sxaiam.ingestion.models import (
    IAMGroup,
    IAMPolicy,
    IAMRole,
    IAMSnapshot,
    IAMUser,
    PolicyDocument,
    PolicyStatement,
)
from sxaiam.resolver.engine import PolicyResolver
from sxaiam.resolver.models import EffectivePermission, ResolvedIdentity

# ---------------------------------------------------------------------------
# Constantes del sandbox
# ---------------------------------------------------------------------------

ACCOUNT_ID = "123456789012"

# ARNs de usuarios
LOW_PRIV_ARN  = f"arn:aws:iam::{ACCOUNT_ID}:user/low_priv_user"
DEV_ARN       = f"arn:aws:iam::{ACCOUNT_ID}:user/developer_user"
READONLY_ARN  = f"arn:aws:iam::{ACCOUNT_ID}:user/readonly_user"
SUPPORT_ARN   = f"arn:aws:iam::{ACCOUNT_ID}:user/support_user"

# ARNs de roles
CI_ROLE_ARN     = f"arn:aws:iam::{ACCOUNT_ID}:role/ci_role"
ADMIN_ROLE_ARN  = f"arn:aws:iam::{ACCOUNT_ID}:role/admin_role"
PRIV_USER_ARN   = f"arn:aws:iam::{ACCOUNT_ID}:user/privileged_user"

# ---------------------------------------------------------------------------
# Helpers para construir el snapshot mínimo
# ---------------------------------------------------------------------------

def _stmt(effect: str, actions: list[str], resources: list[str]) -> PolicyStatement:
    return PolicyStatement(
        effect=effect,
        action=actions,
        resource=resources,
        principal=None,
        condition=None,
    )


def _inline_doc(actions: list[str], resources: list[str] | None = None) -> PolicyDocument:
    return PolicyDocument(
        statements=[_stmt("Allow", actions, resources or ["*"])]
    )


def _make_user(arn: str, name: str, inline_actions: list[str]) -> IAMUser:
    return IAMUser(
        arn=arn,
        user_name=name,
        user_id=f"AIDA{name.upper()[:12]}",
        path="/",
        inline_policies={"sandbox-policy": _inline_doc(inline_actions)},
        attached_policies=[],
        groups=[],
    )


def _make_role(
    arn: str,
    name: str,
    inline_actions: list[str],
    trust_principals: list[str] | None = None,
) -> IAMRole:
    trust_doc = None
    if trust_principals:
        trust_doc = PolicyDocument(
            statements=[
                PolicyStatement(
                    effect="Allow",
                    action=["sts:AssumeRole"],
                    resource=["*"],
                    principal={"AWS": trust_principals},
                    condition=None,
                )
            ]
        )
    return IAMRole(
        arn=arn,
        role_name=name,
        role_id=f"AROA{name.upper()[:12]}",
        path="/",
        assume_role_policy_document=trust_doc,
        inline_policies={"sandbox-policy": _inline_doc(inline_actions)} if inline_actions else {},
        attached_policies=[],
    )


# ---------------------------------------------------------------------------
# Fixture principal — snapshot del sandbox
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sandbox_snapshot() -> IAMSnapshot:
    """
    IAMSnapshot que replica el sandbox Terraform con las 5 identidades
    vulnerables. Cada identidad tiene exactamente los permisos que
    activan su técnica de escalación.
    """
    # path1: low_priv_user con iam:CreatePolicyVersion
    low_priv = _make_user(LOW_PRIV_ARN, "low_priv_user", ["iam:CreatePolicyVersion"])

    # path2: developer_user con iam:PassRole + lambda:CreateFunction + InvokeFunction
    developer = _make_user(DEV_ARN, "developer_user", [
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
    ])

    # path4: readonly_user con iam:AttachUserPolicy
    readonly = _make_user(READONLY_ARN, "readonly_user", ["iam:AttachUserPolicy"])

    # path5: support_user con iam:CreateAccessKey (sobre otro usuario)
    support = _make_user(SUPPORT_ARN, "support_user", ["iam:CreateAccessKey"])

    # privileged_user — víctima de path5 (support puede crear sus access keys)
    privileged = _make_user(PRIV_USER_ARN, "privileged_user", ["*"])

    # path3: ci_role con sts:AssumeRole hacia admin_role
    ci_role = _make_role(
        CI_ROLE_ARN,
        "ci_role",
        inline_actions=["sts:AssumeRole"],
        trust_principals=[DEV_ARN],   # developer puede asumir ci_role
    )

    # admin_role — destino de ci_role (tiene permisos admin)
    admin_role = _make_role(
        ADMIN_ROLE_ARN,
        "admin_role",
        inline_actions=["*"],
        trust_principals=[CI_ROLE_ARN],  # ci_role puede asumir admin_role
    )

    return IAMSnapshot(
        users=[low_priv, developer, readonly, support, privileged],
        roles=[ci_role, admin_role],
        groups=[],
        managed_policies=[],
        scps=[],
    )


@pytest.fixture(scope="module")
def resolved_identities(sandbox_snapshot: IAMSnapshot) -> list[ResolvedIdentity]:
    """Resuelve permisos efectivos para todas las identidades del snapshot."""
    resolver = PolicyResolver(sandbox_snapshot)
    return resolver.resolve_all()


@pytest.fixture(scope="module")
def escalation_paths(
    sandbox_snapshot: IAMSnapshot,
    resolved_identities: list[ResolvedIdentity],
) -> list:
    """Ejecuta el pipeline completo y devuelve todas las rutas encontradas."""
    graph  = AttackGraph()
    G      = graph.build(sandbox_snapshot, resolved_identities)
    finder = PathFinder(G)
    return finder.find_all_paths()


# ---------------------------------------------------------------------------
# Tests 3q — 5/5 rutas detectadas
# ---------------------------------------------------------------------------

class TestFivePathsDetected:
    """Verifica que las 5 técnicas del sandbox generan al menos una ruta cada una."""

    def _get_techniques(self, paths: list) -> set[str]:
        techniques = set()
        for path in paths:
            for step in path.steps:
                techniques.add(step.technique_id)
        return techniques

    def test_at_least_five_paths_found(self, escalation_paths: list):
        """Deben detectarse al menos 5 rutas de escalación."""
        assert len(escalation_paths) >= 5, (
            f"Se esperaban al menos 5 rutas, se encontraron {len(escalation_paths)}"
        )

    def test_create_policy_version_detected(self, escalation_paths: list):
        """path1: CreatePolicyVersion debe aparecer en alguna ruta."""
        techniques = self._get_techniques(escalation_paths)
        assert any("CreatePolicyVersion" in t for t in techniques), (
            f"CreatePolicyVersion no detectado. Técnicas encontradas: {techniques}"
        )

    def test_passrole_lambda_detected(self, escalation_paths: list):
        """path2: PassRole+Lambda debe aparecer en alguna ruta."""
        techniques = self._get_techniques(escalation_paths)
        assert any("PassRole" in t or "Lambda" in t for t in techniques), (
            f"PassRole+Lambda no detectado. Técnicas encontradas: {techniques}"
        )

    def test_attach_policy_detected(self, escalation_paths: list):
        """path4: AttachUserPolicy debe aparecer en alguna ruta."""
        techniques = self._get_techniques(escalation_paths)
        assert any("Attach" in t for t in techniques), (
            f"AttachPolicy no detectado. Técnicas encontradas: {techniques}"
        )

    def test_create_access_key_detected(self, escalation_paths: list):
        """path5: CreateAccessKey debe aparecer en alguna ruta."""
        techniques = self._get_techniques(escalation_paths)
        assert any("AccessKey" in t or "CreateAccessKey" in t for t in techniques), (
            f"CreateAccessKey no detectado. Técnicas encontradas: {techniques}"
        )

    def test_asume_role_chain_or_trust_detected(self, escalation_paths: list):
        """path3: AssumeRole chain debe aparecer como técnica o trust_policy."""
        techniques = self._get_techniques(escalation_paths)
        assert any(
            "AssumeRole" in t or "trust_policy" in t for t in techniques
        ), (
            f"AssumeRole/trust_policy no detectado. Técnicas encontradas: {techniques}"
        )

    def test_low_priv_user_has_path(self, escalation_paths: list):
        """low_priv_user debe tener al menos una ruta de escalación."""
        user_paths = [p for p in escalation_paths if p.origin_arn == LOW_PRIV_ARN]
        assert len(user_paths) >= 1, "low_priv_user no tiene rutas de escalación"

    def test_developer_user_has_path(self, escalation_paths: list):
        """developer_user debe tener al menos una ruta de escalación."""
        user_paths = [p for p in escalation_paths if p.origin_arn == DEV_ARN]
        assert len(user_paths) >= 1, "developer_user no tiene rutas de escalación"

    def test_readonly_user_has_path(self, escalation_paths: list):
        """readonly_user debe tener al menos una ruta de escalación."""
        user_paths = [p for p in escalation_paths if p.origin_arn == READONLY_ARN]
        assert len(user_paths) >= 1, "readonly_user no tiene rutas de escalación"

    def test_support_user_has_path(self, escalation_paths: list):
        """support_user debe tener al menos una ruta de escalación."""
        user_paths = [p for p in escalation_paths if p.origin_arn == SUPPORT_ARN]
        assert len(user_paths) >= 1, "support_user no tiene rutas de escalación"


# ---------------------------------------------------------------------------
# Tests 3r — evidencia explícita en cada ruta
# ---------------------------------------------------------------------------

class TestExplicitEvidence:
    """Verifica que cada ruta tiene evidencia explícita y bien formada."""

    def test_every_path_has_steps(self, escalation_paths: list):
        """Ninguna ruta debe estar vacía de steps."""
        for path in escalation_paths:
            assert len(path.steps) >= 1, (
                f"Ruta {path.path_id} desde {path.origin_name} no tiene steps"
            )

    def test_every_step_has_evidence(self, escalation_paths: list):
        """Cada step debe tener al menos un item de evidencia."""
        for path in escalation_paths:
            for step in path.steps:
                # trust_policy steps pueden tener evidencia mínima
                assert len(step.evidence) >= 1, (
                    f"Step {step.step_number} en ruta {path.path_id} "
                    f"({step.technique_id}) no tiene evidencia"
                )

    def test_evidence_references_iam_action(self, escalation_paths: list):
        """La evidencia debe referenciar una acción IAM concreta (contiene ':')."""
        for path in escalation_paths:
            for step in path.steps:
                for ev in step.evidence:
                    assert ":" in ev, (
                        f"Evidencia sin acción IAM concreta en step "
                        f"{step.step_number} de {path.origin_name}: '{ev}'"
                    )

    def test_every_path_has_severity(self, escalation_paths: list):
        """Cada ruta debe tener una severidad válida."""
        valid_severities = {s.value for s in Severity}
        for path in escalation_paths:
            assert path.severity.value in valid_severities, (
                f"Severidad inválida en ruta {path.path_id}: {path.severity}"
            )

    def test_every_step_has_technique_id(self, escalation_paths: list):
        """Cada step debe tener un technique_id no vacío."""
        for path in escalation_paths:
            for step in path.steps:
                assert step.technique_id, (
                    f"Step {step.step_number} en ruta {path.path_id} "
                    f"no tiene technique_id"
                )

    def test_every_path_has_origin_and_target(self, escalation_paths: list):
        """Todas las rutas deben tener origin_arn y target_arn definidos."""
        for path in escalation_paths:
            assert path.origin_arn, f"Ruta {path.path_id} sin origin_arn"
            assert path.target_arn, f"Ruta {path.path_id} sin target_arn"

    def test_target_is_admin_node(self, escalation_paths: list):
        """El destino de todas las rutas debe ser el AdminNode."""
        for path in escalation_paths:
            assert path.target_arn == "sxaiam::admin", (
                f"Ruta {path.path_id} no llega al AdminNode: {path.target_arn}"
            )

    def test_path_serializes_to_dict(self, escalation_paths: list):
        """Cada ruta debe poder serializarse a dict sin errores."""
        for path in escalation_paths:
            result = path.to_dict()
            assert isinstance(result, dict)
            assert "path_id"    in result
            assert "severity"   in result
            assert "steps"      in result
            assert "origin"     in result
            assert "target"     in result

    def test_path_serializes_to_markdown(self, escalation_paths: list):
        """Cada ruta debe poder serializarse a Markdown sin errores."""
        for path in escalation_paths:
            md = path.to_markdown()
            assert isinstance(md, str)
            assert len(md) > 0
            assert path.origin_name in md


# ---------------------------------------------------------------------------
# Tests de ordenación y estructura del output
# ---------------------------------------------------------------------------

class TestOutputStructure:
    """Verifica que el output está bien ordenado y estructurado."""

    def test_critical_paths_before_high(self, escalation_paths: list):
        """Las rutas CRITICAL deben aparecer antes que las HIGH."""
        severities = [p.severity.value for p in escalation_paths]
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

        for i in range(len(severities) - 1):
            assert order.get(severities[i], 0) >= order.get(severities[i + 1], 0), (
                f"Orden incorrecto: {severities[i]} antes de {severities[i+1]} "
                f"en posición {i}"
            )

    def test_path_ids_are_unique(self, escalation_paths: list):
        """Cada ruta debe tener un path_id único."""
        ids = [p.path_id for p in escalation_paths]
        assert len(ids) == len(set(ids)), "Hay path_ids duplicados"

    def test_step_numbers_are_sequential(self, escalation_paths: list):
        """Los step_number dentro de cada ruta deben ser 1, 2, 3..."""
        for path in escalation_paths:
            for i, step in enumerate(path.steps, start=1):
                assert step.step_number == i, (
                    f"Step_number incorrecto en ruta {path.path_id}: "
                    f"esperado {i}, encontrado {step.step_number}"
                )
