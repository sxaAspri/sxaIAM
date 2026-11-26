"""
sxaiam.providers.gcp.techniques
===============================
Técnicas de escalamiento GCP de la PoC, su clase base y su registry.

Devuelven el **mismo** ``TechniqueMatch`` que las técnicas AWS, para que el
grafo, ``PathFinder`` y los exportadores no cambien. Deuda de nombres:
``origin_arn`` / ``target_arn`` contienen identificadores GCP, no ARNs.

Ids de nodo:
    principal       → miembro IAM (``user:...``, ``serviceAccount:...``, ...)
    service account → ``serviceAccount:<email>`` (mismo nodo como origen y destino)
    admin           → ``sxaiam::admin`` (``AdminNode``)
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from sxaiam.findings.technique_base import Severity, TechniqueMatch
from sxaiam.providers.gcp.models import GCPSnapshot
from sxaiam.providers.gcp.resolver import (
    GCPResolvedPrincipal,
    project_resource,
    service_account_resource,
)
from sxaiam.providers.gcp.roles import ADMIN_ROLE, GET_SA_ACCESS_TOKEN, SET_PROJECT_IAM_POLICY

ADMIN_NODE_ID = "sxaiam::admin"


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class GCPEscalationTechnique(ABC):
    """
    Misma interfaz que ``EscalationTechnique`` (AWS), con tipos GCP en ``check``.
    Sin estado: recibe principal y snapshot en cada llamada.
    """

    @property
    @abstractmethod
    def technique_id(self) -> str: ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def severity(self) -> Severity: ...

    @property
    @abstractmethod
    def required_permissions(self) -> list[str]: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @abstractmethod
    def check(
        self,
        principal: GCPResolvedPrincipal,
        snapshot: GCPSnapshot,
    ) -> list[TechniqueMatch]:
        """Un ``TechniqueMatch`` por objetivo viable; ``[]`` si no aplica."""

    def _build_evidence(
        self,
        principal: GCPResolvedPrincipal,
        permission: str,
        resource: str,
    ) -> list[str]:
        return [p.as_evidence() for p in principal.permissions_for(permission, resource)]


# ---------------------------------------------------------------------------
# Registry (independiente del TechniqueRegistry AWS)
# ---------------------------------------------------------------------------

class GCPTechniqueRegistry:
    """Registry de técnicas GCP, separado del de AWS (no comparte estado)."""

    _techniques: dict[str, GCPEscalationTechnique] = {}

    @classmethod
    def register(cls, technique: GCPEscalationTechnique) -> None:
        cls._techniques[technique.technique_id] = technique

    @classmethod
    def all(cls) -> list[GCPEscalationTechnique]:
        return list(cls._techniques.values())

    @classmethod
    def get(cls, technique_id: str) -> GCPEscalationTechnique | None:
        return cls._techniques.get(technique_id)


# ---------------------------------------------------------------------------
# Técnica 1 — setIamPolicy sobre el proyecto (≈ AWS AttachPolicy)
# ---------------------------------------------------------------------------

class SetProjectIamPolicyTechnique(GCPEscalationTechnique):
    """
    El principal puede modificar la IAM policy del proyecto y se otorga
    ``roles/owner`` a sí mismo. Un salto directo a admin.
    """

    @property
    def technique_id(self) -> str:
        return "gcp-set-iam-policy"

    @property
    def name(self) -> str:
        return "Project setIamPolicy"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def required_permissions(self) -> list[str]:
        return [SET_PROJECT_IAM_POLICY]

    @property
    def description(self) -> str:
        return (
            "The principal can modify the project's IAM policy "
            "(resourcemanager.projects.setIamPolicy) and grant itself roles/owner, "
            "becoming project admin in a single step."
        )

    def check(
        self,
        principal: GCPResolvedPrincipal,
        snapshot: GCPSnapshot,
    ) -> list[TechniqueMatch]:
        project = project_resource(snapshot.project_id)
        if not principal.can(SET_PROJECT_IAM_POLICY, project):
            return []

        return [TechniqueMatch(
            technique_id=self.technique_id,
            technique_name=self.name,
            severity=self.severity,
            origin_arn=principal.member,
            origin_name=principal.name,
            target_arn=ADMIN_NODE_ID,
            target_name=f"{ADMIN_ROLE} on {project}",
            description=self.description,
            evidence=self._build_evidence(principal, SET_PROJECT_IAM_POLICY, project),
            attack_steps=[
                f"gcloud projects get-iam-policy {snapshot.project_id} --format=json",
                f"gcloud projects add-iam-policy-binding {snapshot.project_id} "
                f"--member={principal.member} --role={ADMIN_ROLE}",
            ],
        )]


GCPTechniqueRegistry.register(SetProjectIamPolicyTechnique())


# ---------------------------------------------------------------------------
# Técnica 2 — impersonación de una SA admin (≈ AWS AssumeRole)
# ---------------------------------------------------------------------------

class ServiceAccountImpersonationTechnique(GCPEscalationTechnique):
    """
    El principal puede generar access tokens de una SA y actuar como ella.

    Crea arista principal → SA hacia **cualquier** SA suplantable, sea admin
    o no: el grafo decide si la cadena llega a admin (SA owner → arista
    ``already-admin``; SA con ``setIamPolicy`` → técnica 1; SA que suplanta a
    otra SA → otra arista de esta técnica). Ese es el valor de PathFinder.
    """

    @property
    def technique_id(self) -> str:
        return "gcp-sa-impersonation"

    @property
    def name(self) -> str:
        return "Service account impersonation"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def required_permissions(self) -> list[str]:
        return [GET_SA_ACCESS_TOKEN]

    @property
    def description(self) -> str:
        return (
            "The principal can mint access tokens for a service account "
            "(iam.serviceAccounts.getAccessToken) and act as that service account, "
            "inheriting all of its permissions."
        )

    def check(
        self,
        principal: GCPResolvedPrincipal,
        snapshot: GCPSnapshot,
    ) -> list[TechniqueMatch]:
        matches: list[TechniqueMatch] = []

        for sa in snapshot.service_accounts:
            if sa.member == principal.member:
                continue  # impersonarse a sí misma no escala nada

            sa_resource = service_account_resource(snapshot.project_id, sa.email)
            if not principal.can(GET_SA_ACCESS_TOKEN, sa_resource):
                continue

            matches.append(TechniqueMatch(
                technique_id=self.technique_id,
                technique_name=self.name,
                severity=self.severity,
                origin_arn=principal.member,
                origin_name=principal.name,
                target_arn=sa.member,
                target_name=sa.email,
                description=self.description,
                evidence=self._build_evidence(principal, GET_SA_ACCESS_TOKEN, sa_resource),
                attack_steps=[
                    f"gcloud auth print-access-token --impersonate-service-account={sa.email}",
                    f"gcloud projects get-iam-policy {snapshot.project_id} "
                    f"--impersonate-service-account={sa.email}",
                ],
            ))

        return matches


GCPTechniqueRegistry.register(ServiceAccountImpersonationTechnique())
