"""
Tests for sxaiam.resolver.models

Pure unit tests — no AWS, no moto needed.
Validates the core query logic that the graph engine depends on.
"""

import pytest
from sxaiam.resolver.models import (
    EffectivePermission,
    IdentityType,
    PermissionSource,
    ResolvedIdentity,
)


def make_perm(action: str, resource: str = "*") -> EffectivePermission:
    """Helper to build an EffectivePermission with minimal boilerplate."""
    return EffectivePermission(
        action=action,
        resource=resource,
        source=PermissionSource.MANAGED_POLICY,
        source_name="TestPolicy",
        source_arn="arn:aws:iam::123:policy/TestPolicy",
    )


def make_identity(*actions: str) -> ResolvedIdentity:
    """Helper to build a ResolvedIdentity with given actions on resource *."""
    return ResolvedIdentity(
        arn="arn:aws:iam::123:user/test",
        name="test",
        identity_type=IdentityType.USER,
        effective_permissions=[make_perm(a) for a in actions],
    )


# ---------------------------------------------------------------------------
# EffectivePermission.covers_action
# ---------------------------------------------------------------------------

class TestCoversAction:
    def test_exact_match(self) -> None:
        p = make_perm("iam:PassRole")
        assert p.covers_action("iam:PassRole") is True

    def test_no_match_different_action(self) -> None:
        p = make_perm("iam:PassRole")
        assert p.covers_action("iam:CreateRole") is False

    def test_star_covers_everything(self) -> None:
        p = make_perm("*")
        assert p.covers_action("iam:PassRole") is True
        assert p.covers_action("s3:GetObject") is True

    def test_service_wildcard_iam_star(self) -> None:
        p = make_perm("iam:*")
        assert p.covers_action("iam:PassRole") is True
        assert p.covers_action("iam:CreatePolicyVersion") is True
        assert p.covers_action("s3:GetObject") is False

    def test_prefix_wildcard(self) -> None:
        p = make_perm("s3:Get*")
        assert p.covers_action("s3:GetObject") is True
        assert p.covers_action("s3:GetBucketPolicy") is True
        assert p.covers_action("s3:PutObject") is False

    def test_no_match_different_service(self) -> None:
        p = make_perm("iam:PassRole")
        assert p.covers_action("sts:AssumeRole") is False


# ---------------------------------------------------------------------------
# EffectivePermission.covers_resource
# ---------------------------------------------------------------------------

class TestCoversResource:
    def test_star_covers_any_resource(self) -> None:
        p = make_perm("iam:PassRole", "*")
        assert p.covers_resource("arn:aws:iam::123:role/admin") is True

    def test_exact_resource_match(self) -> None:
        arn = "arn:aws:iam::123:role/admin-role"
        p = make_perm("iam:PassRole", arn)
        assert p.covers_resource(arn) is True

    def test_exact_resource_no_match(self) -> None:
        p = make_perm("iam:PassRole", "arn:aws:iam::123:role/admin-role")
        assert p.covers_resource("arn:aws:iam::123:role/other-role") is False

    def test_prefix_wildcard_resource(self) -> None:
        p = make_perm("iam:PassRole", "arn:aws:iam::123:role/*")
        assert p.covers_resource("arn:aws:iam::123:role/admin") is True
        assert p.covers_resource("arn:aws:iam::123:role/readonly") is True
        assert p.covers_resource("arn:aws:iam::123:user/alice") is False


# ---------------------------------------------------------------------------
# EffectivePermission.as_evidence
# ---------------------------------------------------------------------------

class TestAsEvidence:
    def test_evidence_contains_action(self) -> None:
        p = make_perm("iam:PassRole", "arn:aws:iam::123:role/admin")
        evidence = p.as_evidence()
        assert "iam:PassRole" in evidence

    def test_evidence_contains_source_name(self) -> None:
        p = make_perm("iam:PassRole")
        assert "TestPolicy" in p.as_evidence()


# ---------------------------------------------------------------------------
# ResolvedIdentity.can
# ---------------------------------------------------------------------------

class TestResolvedIdentityCan:
    def test_can_exact_action(self) -> None:
        identity = make_identity("iam:PassRole")
        assert identity.can("iam:PassRole") is True

    def test_cannot_missing_action(self) -> None:
        identity = make_identity("iam:PassRole")
        assert identity.can("iam:CreateRole") is False

    def test_can_with_service_wildcard(self) -> None:
        identity = make_identity("iam:*")
        assert identity.can("iam:CreatePolicyVersion") is True

    def test_can_checks_resource(self) -> None:
        identity = ResolvedIdentity(
            arn="arn:aws:iam::123:user/test",
            name="test",
            identity_type=IdentityType.USER,
            effective_permissions=[
                make_perm("iam:PassRole", "arn:aws:iam::123:role/admin")
            ],
        )
        assert identity.can("iam:PassRole", "arn:aws:iam::123:role/admin") is True
        assert identity.can("iam:PassRole", "arn:aws:iam::123:role/other") is False

    def test_empty_permissions_cannot_do_anything(self) -> None:
        identity = make_identity()
        assert identity.can("iam:PassRole") is False


# ---------------------------------------------------------------------------
# ResolvedIdentity.permissions_for_action
# ---------------------------------------------------------------------------

class TestPermissionsForAction:
    def test_returns_matching_permissions(self) -> None:
        identity = make_identity("iam:PassRole", "iam:CreateRole", "s3:GetObject")
        result = identity.permissions_for_action("iam:PassRole")
        assert len(result) == 1
        assert result[0].action == "iam:PassRole"

    def test_returns_empty_when_no_match(self) -> None:
        identity = make_identity("s3:GetObject")
        result = identity.permissions_for_action("iam:PassRole")
        assert result == []

    def test_wildcard_permission_matches_specific_action(self) -> None:
        identity = make_identity("iam:*")
        result = identity.permissions_for_action("iam:CreatePolicyVersion")
        assert len(result) == 1
