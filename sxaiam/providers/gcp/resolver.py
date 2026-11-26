"""
sxaiam.providers.gcp.resolver
=============================
Calcula los permisos efectivos de cada principal de un ``GCPSnapshot``.

Cada permiso conserva su **origen** (rol + recurso donde está el binding),
que luego se convierte en ``evidence`` de las aristas del grafo.

Recursos (nombres de recurso reales de GCP):
    proyecto        → ``projects/<project_id>``
    service account → ``projects/<project_id>/serviceAccounts/<email>``

Herencia: un permiso otorgado en el proyecto cubre también los recursos hijos
(sus service accounts). Así, ``roles/iam.serviceAccountTokenCreator`` a nivel
proyecto permite suplantar a todas las SAs del proyecto, como en GCP real.

Fuera de alcance (se ignoran con advertencia en ``GCPResolver.warnings``):
    - bindings con ``condition`` (no se evalúan)
    - miembros ``deleted:...`` y tipos de miembro desconocidos
    - roles fuera de ``roles.ROLE_PERMISSIONS`` (custom u otros predefinidos)

Los grupos (``group:``) y dominios (``domain:``) se tratan como principales
normales: no se expanden a sus miembros.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

from sxaiam.providers.gcp.models import GCPBinding, GCPSnapshot
from sxaiam.providers.gcp.roles import ADMIN_ROLE, permissions_for_role

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Recursos
# ---------------------------------------------------------------------------

def project_resource(project_id: str) -> str:
    return f"projects/{project_id}"


def service_account_resource(project_id: str, email: str) -> str:
    return f"projects/{project_id}/serviceAccounts/{email}"


# ---------------------------------------------------------------------------
# Miembros
# ---------------------------------------------------------------------------

class MemberKind(str, Enum):
    USER = "user"
    SERVICE_ACCOUNT = "serviceAccount"
    GROUP = "group"
    DOMAIN = "domain"
    ALL_USERS = "allUsers"
    ALL_AUTHENTICATED_USERS = "allAuthenticatedUsers"


_PREFIXED_KINDS = {
    MemberKind.USER, MemberKind.SERVICE_ACCOUNT, MemberKind.GROUP, MemberKind.DOMAIN,
}
_BARE_KINDS = {MemberKind.ALL_USERS, MemberKind.ALL_AUTHENTICATED_USERS}


def parse_member_kind(member: str) -> MemberKind | None:
    """
    Tipo de un miembro IAM, o ``None`` si no está soportado
    (``deleted:...``, ``principal://...``, prefijos desconocidos).
    """
    for kind in _BARE_KINDS:
        if member == kind.value:
            return kind
    prefix, sep, rest = member.partition(":")
    if not sep or not rest:
        return None
    for kind in _PREFIXED_KINDS:
        if prefix == kind.value:
            return kind
    return None


def member_display_name(member: str) -> str:
    """``user:alice@x.com`` → ``alice@x.com``; ``allUsers`` → ``allUsers``."""
    _, sep, rest = member.partition(":")
    return rest if sep else member


def is_admin_member(member: str, snapshot: GCPSnapshot) -> bool:
    """
    True si el miembro ya es admin: tiene ``roles/owner`` **sin condición**
    a nivel proyecto. Lo usan la técnica de impersonación y el builder.
    """
    return any(
        b.role == ADMIN_ROLE and not b.is_conditional and member in b.members
        for b in snapshot.project_bindings
    )


# ---------------------------------------------------------------------------
# Bindings ignorados
# ---------------------------------------------------------------------------

class IgnoredReason(str, Enum):
    CONDITIONAL = "conditional binding"
    DELETED_MEMBER = "deleted member"
    UNSUPPORTED_MEMBER = "unsupported member type"
    UNSUPPORTED_ROLE = "unsupported role"


@dataclass(frozen=True)
class IgnoredBinding:
    """
    Un binding (o un miembro de un binding) que el resolver no evaluó.
    ``member`` es ``None`` cuando se ignora el binding entero (rol no soportado).
    """

    reason: IgnoredReason
    role: str
    resource: str
    member: str | None = None


# ---------------------------------------------------------------------------
# Resultado
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GCPPermission:
    """
    Un permiso efectivo con su origen.

    ``resource`` es donde está el binding que lo otorga; cubre ese recurso y
    sus hijos.
    """

    permission: str
    resource: str
    role: str

    def covers_resource(self, resource: str) -> bool:
        return resource == self.resource or resource.startswith(self.resource + "/")

    def as_evidence(self) -> str:
        return f"{self.permission} on {self.resource} (via role {self.role})"

    def __str__(self) -> str:
        return f"GCPPermission({self.permission} → {self.resource})"


@dataclass
class GCPResolvedPrincipal:
    """Un principal GCP con todos sus permisos efectivos."""

    member: str
    kind: MemberKind
    permissions: list[GCPPermission] = field(default_factory=list)

    @property
    def name(self) -> str:
        return member_display_name(self.member)

    def can(self, permission: str, resource: str) -> bool:
        return any(
            p.permission == permission and p.covers_resource(resource)
            for p in self.permissions
        )

    def permissions_for(self, permission: str, resource: str) -> list[GCPPermission]:
        """Permisos que otorgan ``permission`` sobre ``resource`` (para evidence)."""
        return [
            p for p in self.permissions
            if p.permission == permission and p.covers_resource(resource)
        ]


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

class GCPResolver:
    """
    Uso::

        resolver = GCPResolver(snapshot)
        principals = resolver.resolve_all()   # dict[member → GCPResolvedPrincipal]
        alice = principals["user:alice@example.com"]
        alice.can("resourcemanager.projects.setIamPolicy", resolver.project_resource)
        resolver.warnings                     # bindings/miembros ignorados (texto)
        resolver.ignored                      # lo mismo, estructurado (para el CLI)
    """

    def __init__(self, snapshot: GCPSnapshot) -> None:
        self._snapshot = snapshot
        self.warnings: list[str] = []
        self.ignored: list[IgnoredBinding] = []

    @property
    def project_resource(self) -> str:
        return project_resource(self._snapshot.project_id)

    def service_account_resource(self, email: str) -> str:
        return service_account_resource(self._snapshot.project_id, email)

    def resolve_all(self) -> dict[str, GCPResolvedPrincipal]:
        self.warnings = []
        self.ignored = []
        principals: dict[str, GCPResolvedPrincipal] = {}

        # Toda SA del snapshot es principal, aunque no tenga permisos
        for sa in self._snapshot.service_accounts:
            principals[sa.member] = GCPResolvedPrincipal(sa.member, MemberKind.SERVICE_ACCOUNT)

        for binding in self._snapshot.project_bindings:
            self._apply_binding(binding, self.project_resource, principals)

        for sa in self._snapshot.service_accounts:
            sa_resource = self.service_account_resource(sa.email)
            for binding in sa.bindings:
                self._apply_binding(binding, sa_resource, principals)

        logger.info("GCPResolver: %d principales resueltos", len(principals))
        return principals

    # ------------------------------------------------------------------

    def _apply_binding(
        self,
        binding: GCPBinding,
        resource: str,
        principals: dict[str, GCPResolvedPrincipal],
    ) -> None:
        if binding.is_conditional:
            for member in binding.members:
                self._ignore(
                    IgnoredBinding(IgnoredReason.CONDITIONAL, binding.role, resource, member),
                    f"binding condicional ignorado: rol {binding.role} para {member} "
                    f"en {resource} (las condiciones IAM no se evalúan)",
                )
            return

        permissions = permissions_for_role(binding.role)
        if permissions is None:
            self._ignore(
                IgnoredBinding(IgnoredReason.UNSUPPORTED_ROLE, binding.role, resource),
                f"rol no soportado ignorado: {binding.role} en {resource} "
                f"(sin mapa de permisos en la PoC)",
            )
            return

        for member in binding.members:
            kind = parse_member_kind(member)
            if kind is None:
                if member.startswith("deleted:"):
                    reason, text = IgnoredReason.DELETED_MEMBER, "miembro eliminado"
                else:
                    reason, text = IgnoredReason.UNSUPPORTED_MEMBER, "tipo de miembro no soportado"
                self._ignore(
                    IgnoredBinding(reason, binding.role, resource, member),
                    f"{text} ignorado: {member} (rol {binding.role} en {resource})",
                )
                continue

            principal = principals.setdefault(member, GCPResolvedPrincipal(member, kind))
            for perm in sorted(permissions):
                grant = GCPPermission(permission=perm, resource=resource, role=binding.role)
                if grant not in principal.permissions:
                    principal.permissions.append(grant)

    def _ignore(self, record: IgnoredBinding, message: str) -> None:
        if record not in self.ignored:
            self.ignored.append(record)
            self.warnings.append(message)
            logger.warning(message)
