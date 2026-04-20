"""
sxaiam.resolver.engine
======================
The PolicyResolver — computes effective permissions for every IAM identity.

Built in three incremental layers:
  Layer 1 (this file): explicit Allow statements, no wildcards, no conditions
  Layer 2: wildcard actions (iam:*, s3:Get*)
  Layer 3: wildcard resources (arn:aws:iam::*:role/*)

Each layer is additive — layer 2 builds on layer 1, layer 3 on layer 2.
The resolver is intentionally separate from the graph engine: it only
computes permissions, never builds edges or paths.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sxaiam.ingestion.models import (
    IAMGroup,
    IAMPolicy,
    IAMRole,
    IAMSnapshot,
    IAMUser,
    PolicyDocument,
    PolicyStatement,
)
from sxaiam.resolver.models import (
    EffectivePermission,
    IdentityType,
    PermissionSource,
    ResolvedIdentity,
)

logger = logging.getLogger(__name__)


class PolicyResolver:
    """
    Computes effective permissions for all identities in an IAMSnapshot.

    Usage:
        resolver = PolicyResolver(snapshot)
        resolved = resolver.resolve_all()
        # resolved is a dict: ARN → ResolvedIdentity

        # Or resolve a single identity:
        identity = resolver.resolve_user(user)
    """

    def __init__(self, snapshot: IAMSnapshot) -> None:
        self._snapshot = snapshot
        # Build a fast lookup: policy ARN → IAMPolicy
        self._policy_map: dict[str, IAMPolicy] = {
            p.arn: p for p in snapshot.policies
        }

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def resolve_all(self) -> dict[str, ResolvedIdentity]:
        """
        Resolve effective permissions for every user and role in the snapshot.
        Returns a dict mapping ARN → ResolvedIdentity.
        """
        resolved: dict[str, ResolvedIdentity] = {}

        for user in self._snapshot.users:
            r = self.resolve_user(user)
            resolved[user.arn] = r
            logger.debug(f"Resolved {user.name}: {len(r.effective_permissions)} permissions")

        for role in self._snapshot.roles:
            r = self.resolve_role(role)
            resolved[role.arn] = r
            logger.debug(f"Resolved {role.name}: {len(r.effective_permissions)} permissions")

        logger.info(f"Resolved {len(resolved)} identities total")
        return resolved

    def resolve_user(self, user: IAMUser) -> ResolvedIdentity:
        """
        Compute effective permissions for a single IAM user.
        Collects permissions from:
          1. Inline policies on the user
          2. Managed policies attached to the user
          3. Inline and managed policies from groups the user belongs to
        """
        permissions: list[EffectivePermission] = []
        denied: list[EffectivePermission] = []

        # 1. User's own inline policies
        for policy_name, doc in user.inline_policies.items():
            allow, deny = self._extract_from_document(
                doc,
                source=PermissionSource.INLINE_POLICY,
                source_name=policy_name,
            )
            permissions.extend(allow)
            denied.extend(deny)

        # 2. User's attached managed policies
        for attached in user.attached_policies:
            policy = self._policy_map.get(attached.arn)
            if policy and policy.document:
                allow, deny = self._extract_from_document(
                    policy.document,
                    source=PermissionSource.MANAGED_POLICY,
                    source_name=attached.name,
                    source_arn=attached.arn,
                )
                permissions.extend(allow)
                denied.extend(deny)

        # 3. Permissions inherited from groups
        for group_name in user.group_names:
            group = next(
                (g for g in self._snapshot.groups if g.name == group_name),
                None,
            )
            if group:
                group_perms, group_denied = self._extract_from_group(group)
                permissions.extend(group_perms)
                denied.extend(group_denied)

        # Apply explicit Deny — removes any matching Allow
        effective = self._apply_denies(permissions, denied)

        return ResolvedIdentity(
            arn=user.arn,
            name=user.name,
            identity_type=IdentityType.USER,
            effective_permissions=effective,
            denied_permissions=denied,
        )

    def resolve_role(self, role: IAMRole) -> ResolvedIdentity:
        """
        Compute effective permissions for a single IAM role.
        Collects permissions from inline and managed policies on the role.
        Note: the trust policy is NOT included here — it's handled by
        the graph engine directly when building AssumeRole edges.
        """
        permissions: list[EffectivePermission] = []
        denied: list[EffectivePermission] = []

        # Role's inline policies
        for policy_name, doc in role.inline_policies.items():
            allow, deny = self._extract_from_document(
                doc,
                source=PermissionSource.INLINE_POLICY,
                source_name=policy_name,
            )
            permissions.extend(allow)
            denied.extend(deny)

        # Role's attached managed policies
        for attached in role.attached_policies:
            policy = self._policy_map.get(attached.arn)
            if policy and policy.document:
                allow, deny = self._extract_from_document(
                    policy.document,
                    source=PermissionSource.MANAGED_POLICY,
                    source_name=attached.name,
                    source_arn=attached.arn,
                )
                permissions.extend(allow)
                denied.extend(deny)

        effective = self._apply_denies(permissions, denied)

        return ResolvedIdentity(
            arn=role.arn,
            name=role.name,
            identity_type=IdentityType.ROLE,
            effective_permissions=effective,
            denied_permissions=denied,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_from_document(
        self,
        doc: PolicyDocument,
        source: PermissionSource,
        source_name: str,
        source_arn: str = "",
    ) -> tuple[list[EffectivePermission], list[EffectivePermission]]:
        """
        Extract Allow and Deny permissions from a policy document.
        Returns (allow_list, deny_list).

        Layer 1: handles explicit statements only.
        Wildcards in actions and resources are preserved as-is in the
        EffectivePermission — covers_action() and covers_resource()
        handle the matching at query time.
        """
        allows: list[EffectivePermission] = []
        denies: list[EffectivePermission] = []

        for stmt in doc.statements:
            perms = self._extract_from_statement(
                stmt, source, source_name, source_arn
            )
            if stmt.effect == "Allow":
                allows.extend(perms)
            elif stmt.effect == "Deny":
                denies.extend(perms)

        return allows, denies

    def _extract_from_statement(
        self,
        stmt: PolicyStatement,
        source: PermissionSource,
        source_name: str,
        source_arn: str = "",
    ) -> list[EffectivePermission]:
        """
        Build EffectivePermission objects from a single policy statement.
        Produces one permission per (action, resource) combination.
        """
        permissions: list[EffectivePermission] = []

        for action in stmt.actions:
            for resource in stmt.resources:
                permissions.append(
                    EffectivePermission(
                        action=action,
                        resource=resource,
                        source=source,
                        source_name=source_name,
                        source_arn=source_arn,
                    )
                )

        return permissions

    def _extract_from_group(
        self, group: IAMGroup
    ) -> tuple[list[EffectivePermission], list[EffectivePermission]]:
        """Extract all permissions from a group's inline and managed policies."""
        allows: list[EffectivePermission] = []
        denies: list[EffectivePermission] = []

        for policy_name, doc in group.inline_policies.items():
            allow, deny = self._extract_from_document(
                doc,
                source=PermissionSource.GROUP_POLICY,
                source_name=f"{group.name}/{policy_name}",
            )
            allows.extend(allow)
            denies.extend(deny)

        for attached in group.attached_policies:
            policy = self._policy_map.get(attached.arn)
            if policy and policy.document:
                allow, deny = self._extract_from_document(
                    policy.document,
                    source=PermissionSource.GROUP_POLICY,
                    source_name=f"{group.name}/{attached.name}",
                    source_arn=attached.arn,
                )
                allows.extend(allow)
                denies.extend(deny)

        return allows, denies

    def _apply_denies(
        self,
        allows: list[EffectivePermission],
        denies: list[EffectivePermission],
    ) -> list[EffectivePermission]:
        """
        Remove any Allow permission that is overridden by an explicit Deny.
        In IAM, explicit Deny always wins — regardless of order.

        Layer 1: exact match only (action == action, resource == resource).
        Wildcard deny matching is a Layer 3 concern.
        """
        if not denies:
            return allows

        def is_denied(perm: EffectivePermission) -> bool:
            return any(
                d.covers_action(perm.action) and d.covers_resource(perm.resource)
                for d in denies
            )

        return [p for p in allows if not is_denied(p)]
