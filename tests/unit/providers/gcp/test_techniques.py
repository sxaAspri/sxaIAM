"""
Tests for sxaiam.providers.gcp.techniques

Positivo + negativo por técnica sobre el fixture, más snapshots sintéticos
para securityAdmin, editor, herencia y condiciones.
"""

from pathlib import Path
from typing import Any

import pytest

from sxaiam.findings.registry import TechniqueRegistry
from sxaiam.findings.technique_base import Severity, TechniqueMatch
from sxaiam.providers.gcp.loader import load_snapshot, parse_snapshot
from sxaiam.providers.gcp.models import GCPSnapshot
from sxaiam.providers.gcp.resolver import GCPResolvedPrincipal, GCPResolver, is_admin_member
from sxaiam.providers.gcp.techniques import (
    ADMIN_NODE_ID,
    GCPTechniqueRegistry,
    ServiceAccountImpersonationTechnique,
    SetProjectIamPolicyTechnique,
)

FIXTURE = Path(__file__).parents[3] / "fixtures" / "gcp" / "vulnerable_project.json"

DEPLOYER = "deployer@acme-poc-123456.iam.gserviceaccount.com"
READER = "reader@acme-poc-123456.iam.gserviceaccount.com"
CI_RUNNER = "ci-runner@acme-poc-123456.iam.gserviceaccount.com"
ALICE = "user:alice@acme-poc.example"
BOB = "user:bob@acme-poc.example"
CAROL = "user:carol@acme-poc.example"

SET_IAM = SetProjectIamPolicyTechnique()
IMPERSONATE = ServiceAccountImpersonationTechnique()


@pytest.fixture(scope="module")
def snapshot() -> GCPSnapshot:
    return load_snapshot(FIXTURE)


@pytest.fixture(scope="module")
def principals(snapshot: GCPSnapshot) -> dict[str, GCPResolvedPrincipal]:
    return GCPResolver(snapshot).resolve_all()


def synthetic(
    project_bindings: list[dict[str, Any]],
    service_accounts: list[dict[str, Any]] | None = None,
) -> tuple[GCPSnapshot, dict[str, GCPResolvedPrincipal]]:
    snap = parse_snapshot({
        "project_id": "p",
        "project_iam_policy": {"bindings": project_bindings},
        "service_accounts": service_accounts or [],
    })
    return snap, GCPResolver(snap).resolve_all()


def sa(email: str, *bindings: dict[str, Any]) -> dict[str, Any]:
    return {"email": email, "iam_policy": {"bindings": list(bindings)}}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_registry_has_both_techniques() -> None:
    assert {t.technique_id for t in GCPTechniqueRegistry.all()} == {
        "gcp-set-iam-policy",
        "gcp-sa-impersonation",
    }


def test_registry_get() -> None:
    assert isinstance(GCPTechniqueRegistry.get("gcp-set-iam-policy"), SetProjectIamPolicyTechnique)
    assert GCPTechniqueRegistry.get("create-policy-version") is None


def test_aws_registry_untouched() -> None:
    aws_ids = {t.technique_id for t in TechniqueRegistry.all()}
    assert len(aws_ids) == 14
    assert not any(tid.startswith("gcp-") for tid in aws_ids)


# ---------------------------------------------------------------------------
# Técnica 1 — gcp-set-iam-policy
# ---------------------------------------------------------------------------

def test_set_iam_policy_positive_alice(
    snapshot: GCPSnapshot, principals: dict[str, GCPResolvedPrincipal],
) -> None:
    [match] = SET_IAM.check(principals[ALICE], snapshot)
    assert isinstance(match, TechniqueMatch)
    assert match.technique_id == "gcp-set-iam-policy"
    assert match.severity is Severity.CRITICAL
    assert match.origin_arn == ALICE
    assert match.origin_name == "alice@acme-poc.example"
    assert match.target_arn == ADMIN_NODE_ID
    assert any("roles/resourcemanager.projectIamAdmin" in e for e in match.evidence)
    assert any("add-iam-policy-binding" in s for s in match.attack_steps)


@pytest.mark.parametrize("member", [
    BOB,
    CAROL,
    f"serviceAccount:{READER}",
    f"serviceAccount:{CI_RUNNER}",
])
def test_set_iam_policy_negative(
    member: str, snapshot: GCPSnapshot, principals: dict[str, GCPResolvedPrincipal],
) -> None:
    assert SET_IAM.check(principals[member], snapshot) == []


def test_set_iam_policy_ignores_conditional_binding() -> None:
    snap, principals = synthetic([
        {"role": "roles/resourcemanager.projectIamAdmin", "members": ["user:dave@x"],
         "condition": {"title": "t", "expression": "true"}},
        {"role": "roles/viewer", "members": ["user:dave@x"]},
    ])
    assert SET_IAM.check(principals["user:dave@x"], snap) == []


def test_set_iam_policy_positive_security_admin() -> None:
    snap, principals = synthetic([
        {"role": "roles/iam.securityAdmin", "members": ["user:sec@x"]},
    ])
    [match] = SET_IAM.check(principals["user:sec@x"], snap)
    assert match.target_arn == ADMIN_NODE_ID
    assert any("roles/iam.securityAdmin" in e for e in match.evidence)


def test_set_iam_policy_negative_editor() -> None:
    snap, principals = synthetic([{"role": "roles/editor", "members": ["user:ed@x"]}])
    assert SET_IAM.check(principals["user:ed@x"], snap) == []


# ---------------------------------------------------------------------------
# Técnica 2 — gcp-sa-impersonation
# ---------------------------------------------------------------------------

def test_impersonation_positive_bob(
    snapshot: GCPSnapshot, principals: dict[str, GCPResolvedPrincipal],
) -> None:
    [match] = IMPERSONATE.check(principals[BOB], snapshot)
    assert match.technique_id == "gcp-sa-impersonation"
    assert match.severity is Severity.HIGH
    assert match.origin_arn == BOB
    assert match.target_arn == f"serviceAccount:{DEPLOYER}"
    assert match.target_name == DEPLOYER
    assert any("roles/iam.serviceAccountTokenCreator" in e for e in match.evidence)
    assert any("--impersonate-service-account" in s for s in match.attack_steps)


def test_impersonation_positive_non_admin_sa(
    snapshot: GCPSnapshot, principals: dict[str, GCPResolvedPrincipal],
) -> None:
    # Arista hacia cualquier SA suplantable: reader solo es viewer, pero hay arista.
    # Que no llegue a admin lo decide el grafo (Fase 4), no la técnica.
    [match] = IMPERSONATE.check(principals[f"serviceAccount:{CI_RUNNER}"], snapshot)
    assert match.target_arn == f"serviceAccount:{READER}"
    assert match.severity is Severity.HIGH


@pytest.mark.parametrize("member", [ALICE, CAROL, f"serviceAccount:{READER}"])
def test_impersonation_negative_no_token_creator(
    member: str, snapshot: GCPSnapshot, principals: dict[str, GCPResolvedPrincipal],
) -> None:
    assert IMPERSONATE.check(principals[member], snapshot) == []


def test_impersonation_project_level_token_creator_hits_every_sa() -> None:
    snap, principals = synthetic(
        [
            {"role": "roles/iam.serviceAccountTokenCreator", "members": ["user:eve@x"]},
            {"role": "roles/owner", "members": ["serviceAccount:admin@p.iam.gserviceaccount.com"]},
        ],
        [sa("admin@p.iam.gserviceaccount.com"), sa("plain@p.iam.gserviceaccount.com")],
    )
    matches = IMPERSONATE.check(principals["user:eve@x"], snap)
    assert {m.target_arn for m in matches} == {
        "serviceAccount:admin@p.iam.gserviceaccount.com",
        "serviceAccount:plain@p.iam.gserviceaccount.com",
    }


def test_impersonation_ignores_conditional_token_creator() -> None:
    snap, principals = synthetic(
        [{"role": "roles/viewer", "members": ["user:eve@x"]}],
        [sa("t@p.iam.gserviceaccount.com",
            {"role": "roles/iam.serviceAccountTokenCreator", "members": ["user:eve@x"],
             "condition": {"title": "t", "expression": "true"}})],
    )
    assert IMPERSONATE.check(principals["user:eve@x"], snap) == []


def test_impersonation_conditional_owner_is_not_admin() -> None:
    # is_admin_member ignora roles/owner condicional (lo usará el builder)
    target = "serviceAccount:t@p.iam.gserviceaccount.com"
    snap, _ = synthetic(
        [{"role": "roles/owner", "members": [target],
          "condition": {"title": "t", "expression": "true"}}],
        [sa("t@p.iam.gserviceaccount.com")],
    )
    assert not is_admin_member(target, snap)


def test_impersonation_skips_self() -> None:
    me = "serviceAccount:me@p.iam.gserviceaccount.com"
    snap, principals = synthetic(
        [{"role": "roles/owner", "members": [me]}],
        [sa("me@p.iam.gserviceaccount.com",
            {"role": "roles/iam.serviceAccountTokenCreator", "members": [me]})],
    )
    assert IMPERSONATE.check(principals[me], snap) == []


# ---------------------------------------------------------------------------
# is_admin_member
# ---------------------------------------------------------------------------

def test_is_admin_member(snapshot: GCPSnapshot) -> None:
    assert is_admin_member(f"serviceAccount:{DEPLOYER}", snapshot)
    assert not is_admin_member(ALICE, snapshot)       # projectIamAdmin no es admin
    assert not is_admin_member(f"serviceAccount:{READER}", snapshot)


def test_editor_is_not_admin() -> None:
    snap, _ = synthetic([{"role": "roles/editor", "members": ["user:ed@x"]}])
    assert not is_admin_member("user:ed@x", snap)
