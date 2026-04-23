"""
sxaiam.resolver.engine
======================
The PolicyResolver — computes effective permissions for every IAM identity.

Three layers of resolution, all active:
  Layer 1: explicit Allow/Deny statements
  Layer 2: wildcard actions  — iam:*, s3:Get*, *
  Layer 3: wildcard resources — arn:aws:iam::*:role/*, *

Wildcards are handled at query time by EffectivePermission.covers_action()
and covers_resource() — the engine stores permissions as-is and lets
those methods do the matching. This means layers 2 and 3 require no
extra parsing logic here — they work automatically once the permission
objects are stored correctly.

The resolver is strictly read-only: it computes permissions, never
builds edges, paths, or any graph structure.
"""

from __future__ import annotations

import logging

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

    Layers active in this version:
      ✅ Layer 1 — explicit Allow without conditions
      ✅ Layer 2 — wildcard actions: iam:*, s3:Get*, *
      ✅ Layer 3 — wildcard resources: arn:aws:iam::*:role/*, *

    Not yet covered (documented gaps):
       Condition keys (aws:RequestedRegion, aws:PrincipalTag, etc.)
       Permission boundaries
       Session policies (sts:AssumeRole with inline session policy)

    Usage:
        resolver = PolicyResolver(snapshot)
        resolved = resolver.resolve_all()
        # resolved: dict[arn → ResolvedIdentity]

        identity = resolver.resolve_user(user)
        if identity.can("iam:PassRole", role_arn):
            ...
    """

    def __init__(self, snapshot: IAMSnapshot) -> None:
        self._snapshot = snapshot
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
            logger.debug(
                f"Resolved user {user.name}: "
                f"{len(r.effective_permissions)} effective permissions"
            )

        for role in self._snapshot.roles:
            r = self.resolve_role(role)
            resolved[role.arn] = r
            logger.debug(
                f"Resolved role {role.name}: "
                f"{len(r.effective_permissions)} effective permissions"
            )

        logger.info(f"Resolved {len(resolved)} identities total")
        return resolved

    def resolve_user(self, user: IAMUser) -> ResolvedIdentity:
        """
        Compute effective permissions for a single IAM user.

        Collection order (matches AWS evaluation logic):
          1. User inline policies
          2. User attached managed policies
          3. Group inline policies (all groups the user belongs to)
          4. Group attached managed policies

        After collection, explicit Deny removes matching Allows.
        Wildcard matching (layers 2 + 3) is handled automatically
        by EffectivePermission.covers_action() / covers_resource().
        """
        allows: list[EffectivePermission] = []
        denies: list[EffectivePermission] = []

        # 1. User inline policies
        for policy_name, doc in user.inline_policies.items():
            a, d = self._extract_from_document(
                doc,
                source=PermissionSource.INLINE_POLICY,
                source_name=policy_name,
            )
            allows.extend(a)
            denies.extend(d)

        # 2. User attached managed policies
        for attached in user.attached_policies:
            policy = self._policy_map.get(attached.arn)
            if policy and policy.document:
                a, d = self._extract_from_document(
                    policy.document,
                    source=PermissionSource.MANAGED_POLICY,
                    source_name=attached.name,
                    source_arn=attached.arn,
                )
                allows.extend(a)
                denies.extend(d)

        # 3 + 4. Group policies
        for group_name in user.group_names:
            group = next(
                (g for g in self._snapshot.groups if g.name == group_name),
                None,
            )
            if group:
                ga, gd = self._extract_from_group(group)
                allows.extend(ga)
                denies.extend(gd)

        effective = self._apply_denies(allows, denies)

        return ResolvedIdentity(
            arn=user.arn,
            name=user.name,
            identity_type=IdentityType.USER,
            effective_permissions=effective,
            denied_permissions=denies,
        )

    def resolve_role(self, role: IAMRole) -> ResolvedIdentity:
        """
        Compute effective permissions for a single IAM role.

        Note: the role's trust policy is NOT resolved here.
        The trust policy determines WHO can assume the role — that's
        an edge in the attack graph, not a permission of the role itself.
        The graph engine handles trust policies directly.
        """
        allows: list[EffectivePermission] = []
        denies: list[EffectivePermission] = []

        for policy_name, doc in role.inline_policies.items():
            a, d = self._extract_from_document(
                doc,
                source=PermissionSource.INLINE_POLICY,
                source_name=policy_name,
            )
            allows.extend(a)
            denies.extend(d)

        for attached in role.attached_policies:
            policy = self._policy_map.get(attached.arn)
            if policy and policy.document:
                a, d = self._extract_from_document(
                    policy.document,
                    source=PermissionSource.MANAGED_POLICY,
                    source_name=attached.name,
                    source_arn=attached.arn,
                )
                allows.extend(a)
                denies.extend(d)

        effective = self._apply_denies(allows, denies)

        return ResolvedIdentity(
            arn=role.arn,
            name=role.name,
            identity_type=IdentityType.ROLE,
            effective_permissions=effective,
            denied_permissions=denies,
        )

    def has_permission(
        self,
        identity: ResolvedIdentity,
        action: str,
        resource: str = "*",
    ) -> bool:
        """
        Convenience method: does this identity have the given permission?

        Layers 2 + 3 active: handles wildcards in both action and resource.

        Examples:
            resolver.has_permission(dev, "iam:PassRole", admin_role_arn)
            resolver.has_permission(ci,  "sts:AssumeRole", "*")
        """
        return identity.can(action, resource)

    def get_evidence(
        self,
        identity: ResolvedIdentity,
        action: str,
    ) -> list[EffectivePermission]:
        """
        Return all permissions that cover the given action for this identity.
        Used by the graph engine to attach evidence to attack path edges.

        Wildcard matching active: 'iam:*' covers 'iam:CreatePolicyVersion'.
        """
        return identity.permissions_for_action(action)

    # ------------------------------------------------------------------
    # Internal extraction helpers
    # ------------------------------------------------------------------

    def _extract_from_document(
        self,
        doc: PolicyDocument,
        source: PermissionSource,
        source_name: str,
        source_arn: str = "",
    ) -> tuple[list[EffectivePermission], list[EffectivePermission]]:
        """
        Extract Allow and Deny permissions from a full policy document.

        Layer 2 + 3 note: wildcards like 'iam:*' and 'arn:aws:iam::*:role/*'
        are stored as-is in the EffectivePermission objects. The matching
        happens at query time via covers_action() and covers_resource().
        This means we don't need to expand wildcards here — they resolve
        correctly when the graph engine asks "can this identity do X on Y?".
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
        Build EffectivePermission objects from a single statement.

        One permission per (action, resource) pair. Wildcards are preserved
        verbatim — 'iam:*' stays 'iam:*', 'arn:aws:iam::*:role/*' stays as-is.
        The covers_action() and covers_resource() methods handle expansion.
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
        self,
        group: IAMGroup,
    ) -> tuple[list[EffectivePermission], list[EffectivePermission]]:
        """Extract all permissions from a group's inline and managed policies."""
        allows: list[EffectivePermission] = []
        denies: list[EffectivePermission] = []

        for policy_name, doc in group.inline_policies.items():
            a, d = self._extract_from_document(
                doc,
                source=PermissionSource.GROUP_POLICY,
                source_name=f"{group.name}/{policy_name}",
            )
            allows.extend(a)
            denies.extend(d)

        for attached in group.attached_policies:
            policy = self._policy_map.get(attached.arn)
            if policy and policy.document:
                a, d = self._extract_from_document(
                    policy.document,
                    source=PermissionSource.GROUP_POLICY,
                    source_name=f"{group.name}/{attached.name}",
                    source_arn=attached.arn,
                )
                allows.extend(a)
                denies.extend(d)

        return allows, denies

    # ------------------------------------------------------------------
    # Deny resolution — Layer 2 + 3 active
    # ------------------------------------------------------------------

    def _apply_denies(
        self,
        allows: list[EffectivePermission],
        denies: list[EffectivePermission],
    ) -> list[EffectivePermission]:
        """
        Remove any Allow that is overridden by an explicit Deny.
        In IAM, explicit Deny always wins — regardless of order or source.

        A deny blocks an allow when the deny's action and resource
        cover the allow's action and resource respectively.

        Note: wildcard allows (iam:*) are NOT removed by specific denies
        (iam:DeleteRole) — the deny blocks at query time via can().
        This matches AWS evaluation semantics where you keep the broad
        allow but the specific deny wins at access decision time.
        """
        if not denies:
            return allows

        def is_denied(perm: EffectivePermission) -> bool:
            return any(
                deny.covers_action(perm.action)
                and deny.covers_resource(perm.resource)
                for deny in denies
            )

        return [p for p in allows if not is_denied(p)]