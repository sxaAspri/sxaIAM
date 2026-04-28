"""
sxaiam.resolver.models
======================
Data models representing the output of the policy resolver.

These are NOT the same as the ingestion models (IAMUser, IAMRole, etc.).
Those represent what AWS says exists. These represent what the resolver
calculated an identity can actually DO — the effective permissions.

The graph engine consumes these models to build attack path edges.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class IdentityType(str, Enum):
    """The type of IAM identity."""
    USER  = "user"
    ROLE  = "role"
    GROUP = "group"


class PermissionSource(str, Enum):
    """Where a permission came from — used as evidence in findings."""
    INLINE_POLICY   = "inline_policy"
    MANAGED_POLICY  = "managed_policy"
    GROUP_POLICY    = "group_policy"
    SCP             = "scp"


@dataclass(frozen=True)
class EffectivePermission:
    """
    A single effective permission that an identity can exercise.

    'Effective' means it survived the full evaluation:
    — the action is explicitly Allowed
    — no Deny overrides it (explicit Deny always wins)
    — no SCP blocks it at the organization level

    This is the atomic unit the graph engine uses to create edges.

    Example:
        EffectivePermission(
            action="iam:PassRole",
            resource="arn:aws:iam::123:role/admin-role",
            source=PermissionSource.MANAGED_POLICY,
            source_name="DeveloperPermissions",
            source_arn="arn:aws:iam::123:policy/DeveloperPermissions",
        )
    """

    action: str
    """The IAM action, e.g. 'iam:PassRole', 'lambda:CreateFunction'"""

    resource: str
    """The resource ARN this action applies to. '*' means any resource."""

    source: PermissionSource
    """Where this permission comes from."""

    source_name: str
    """Human-readable name of the source policy."""

    source_arn: str = ""
    """ARN of the source policy (empty for inline policies)."""

    def covers_resource(self, resource_arn: str) -> bool:
        """
        True if this permission's resource pattern covers the given ARN.
        Handles:
        - '*'                        → any resource
        - 'arn:aws:iam::*:role/*'    → wildcards en segmentos intermedios
        - 'arn:aws:s3:::my-bucket/*' → prefix wildcard al final
        """
        if self.resource == "*":
            return True

        # Si no hay wildcard, comparación exacta
        if "*" not in self.resource:
            return self.resource == resource_arn

        # Convertir el patrón a matching por segmentos
        import fnmatch
        return fnmatch.fnmatch(resource_arn, self.resource)

    def covers_action(self, action: str) -> bool:
        """
        True if this permission's action pattern covers the given action.
        Handles '*' and service wildcards like 'iam:*' or 's3:Get*'.
        """
        if self.action == "*":
            return True
        if ":" not in self.action:
            return False
        perm_service, perm_op = self.action.split(":", 1)
        req_service, req_op = action.split(":", 1) if ":" in action else ("", action)
        if perm_service != req_service:
            return False
        if perm_op == "*":
            return True
        if perm_op.endswith("*"):
            return req_op.startswith(perm_op[:-1])
        return perm_op == req_op

    def as_evidence(self) -> str:
        """Human-readable evidence string for findings and reports."""
        return (
            f"{self.action} on {self.resource} "
            f"(via {self.source.value}: {self.source_name})"
        )

    def __str__(self) -> str:
        return f"EffectivePermission({self.action} → {self.resource})"


@dataclass
class ResolvedIdentity:
    """
    An IAM identity with all its effective permissions calculated.

    This is what the resolver produces for each user, role, and group.
    The graph engine iterates over ResolvedIdentity objects to build
    the attack graph edges.

    Example:
        ResolvedIdentity(
            arn="arn:aws:iam::123:user/developer",
            name="developer",
            identity_type=IdentityType.USER,
            effective_permissions=[
                EffectivePermission("iam:PassRole", "arn:aws:iam::*:role/*", ...),
                EffectivePermission("lambda:CreateFunction", "*", ...),
            ]
        )
    """

    arn: str
    name: str
    identity_type: IdentityType
    effective_permissions: list[EffectivePermission] = field(default_factory=list)

    # Permissions blocked by an explicit Deny — stored for transparency
    denied_permissions: list[EffectivePermission] = field(default_factory=list)

    def can(self, action: str, resource: str = "*") -> bool:
        """
        True if this identity has an effective permission that covers
        the given action on the given resource, and no deny blocks it.
        """
        has_allow = any(
        p.covers_action(action) and p.covers_resource(resource)
        for p in self.effective_permissions
        )
        if not has_allow:
            return False

        # Explicit deny always wins — check at query time
        is_denied = any(
        d.covers_action(action) and d.covers_resource(resource)
        for d in self.denied_permissions
        )
        return not is_denied

    def permissions_for_action(self, action: str) -> list[EffectivePermission]:
        """
        Return all effective permissions that cover the given action.
        Used by the graph engine to attach evidence to edges.
        """
        return [
            p for p in self.effective_permissions
            if p.covers_action(action)
        ]

    def summary(self) -> str:
        return (
            f"ResolvedIdentity({self.identity_type.value}: {self.name}, "
            f"{len(self.effective_permissions)} effective permissions)"
        )

    def __str__(self) -> str:
        return self.summary()
