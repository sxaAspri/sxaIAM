"""
Tests for sxaiam.resolver.engine — PolicyResolver

Pure unit tests using hand-crafted IAMSnapshot objects.
No AWS, no moto needed — just Python objects.
"""

import pytest
from sxaiam.ingestion.models import (
    AttachedPolicy,
    IAMGroup,
    IAMPolicy,
    IAMRole,
    IAMSnapshot,
    IAMUser,
    PolicyDocument,
)
from sxaiam.resolver.engine import PolicyResolver
from sxaiam.resolver.models import IdentityType, PermissionSource


# ---------------------------------------------------------------------------
# Helpers — build minimal IAM objects for testing
# ---------------------------------------------------------------------------

def make_policy_doc(*actions: str, effect: str = "Allow", resource: str = "*") -> PolicyDocument:
    """Build a simple PolicyDocument with one statement."""
    return PolicyDocument.from_raw({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": effect,
            "Action": list(actions),
            "Resource": resource,
        }]
    })


def make_managed_policy(name: str, arn: str, *actions: str) -> IAMPolicy:
    return IAMPolicy(
        name=name,
        arn=arn,
        policy_id=f"ID-{name}",
        is_aws_managed=False,
        document=make_policy_doc(*actions),
    )


def make_trust_doc() -> PolicyDocument:
    return PolicyDocument.from_raw({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }]
    })


def make_snapshot(
    users: list[IAMUser] | None = None,
    roles: list[IAMRole] | None = None,
    groups: list[IAMGroup] | None = None,
    policies: list[IAMPolicy] | None = None,
) -> IAMSnapshot:
    snapshot = IAMSnapshot(
        account_id="123456789012",
        users=users or [],
        roles=roles or [],
        groups=groups or [],
        policies=policies or [],
    )
    snapshot.build_indexes()
    return snapshot


# ---------------------------------------------------------------------------
# Tests: resolving users
# ---------------------------------------------------------------------------

class TestResolveUser:

    def test_user_with_inline_policy(self) -> None:
        user = IAMUser(
            name="alice",
            arn="arn:aws:iam::123:user/alice",
            user_id="UID1",
            inline_policies={"MyPolicy": make_policy_doc("s3:GetObject")},
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.can("s3:GetObject") is True
        assert result.identity_type == IdentityType.USER

    def test_user_with_attached_managed_policy(self) -> None:
        policy = make_managed_policy(
            "DevPolicy",
            "arn:aws:iam::123:policy/DevPolicy",
            "iam:PassRole",
            "lambda:CreateFunction",
        )
        user = IAMUser(
            name="developer",
            arn="arn:aws:iam::123:user/developer",
            user_id="UID2",
            attached_policies=[
                AttachedPolicy(
                    PolicyName="DevPolicy",
                    PolicyArn="arn:aws:iam::123:policy/DevPolicy",
                )
            ],
        )
        resolver = PolicyResolver(make_snapshot(users=[user], policies=[policy]))
        result = resolver.resolve_user(user)

        assert result.can("iam:PassRole") is True
        assert result.can("lambda:CreateFunction") is True
        assert result.can("iam:CreateRole") is False

    def test_user_inherits_permissions_from_group(self) -> None:
        group = IAMGroup(
            name="developers",
            arn="arn:aws:iam::123:group/developers",
            group_id="GID1",
            inline_policies={"GroupPolicy": make_policy_doc("ec2:DescribeInstances")},
        )
        user = IAMUser(
            name="bob",
            arn="arn:aws:iam::123:user/bob",
            user_id="UID3",
            group_names=["developers"],
        )
        resolver = PolicyResolver(make_snapshot(users=[user], groups=[group]))
        result = resolver.resolve_user(user)

        assert result.can("ec2:DescribeInstances") is True

    def test_user_with_no_policies_has_no_permissions(self) -> None:
        user = IAMUser(
            name="empty",
            arn="arn:aws:iam::123:user/empty",
            user_id="UID4",
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.effective_permissions == []

    def test_explicit_deny_removes_allow(self) -> None:
        allow_doc = make_policy_doc("iam:*", effect="Allow")
        deny_doc = make_policy_doc("iam:DeleteRole", effect="Deny")
        user = IAMUser(
            name="restricted",
            arn="arn:aws:iam::123:user/restricted",
            user_id="UID5",
            inline_policies={
                "AllowAll": allow_doc,
                "DenyDelete": deny_doc,
            },
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.can("iam:CreateRole") is True
        assert result.can("iam:DeleteRole") is False

    def test_permission_source_is_recorded(self) -> None:
        policy = make_managed_policy(
            "TestPolicy",
            "arn:aws:iam::123:policy/TestPolicy",
            "s3:GetObject",
        )
        user = IAMUser(
            name="alice",
            arn="arn:aws:iam::123:user/alice",
            user_id="UID6",
            attached_policies=[
                AttachedPolicy(
                    PolicyName="TestPolicy",
                    PolicyArn="arn:aws:iam::123:policy/TestPolicy",
                )
            ],
        )
        resolver = PolicyResolver(make_snapshot(users=[user], policies=[policy]))
        result = resolver.resolve_user(user)

        perms = result.permissions_for_action("s3:GetObject")
        assert len(perms) == 1
        assert perms[0].source == PermissionSource.MANAGED_POLICY
        assert perms[0].source_name == "TestPolicy"


# ---------------------------------------------------------------------------
# Tests: resolving roles
# ---------------------------------------------------------------------------

class TestResolveRole:

    def test_role_with_managed_policy(self) -> None:
        policy = make_managed_policy(
            "AdminAccess",
            "arn:aws:iam::aws:policy/AdministratorAccess",
            "*",
        )
        role = IAMRole(
            name="admin-role",
            arn="arn:aws:iam::123:role/admin-role",
            role_id="RID1",
            trust_policy=make_trust_doc(),
            attached_policies=[
                AttachedPolicy(
                    PolicyName="AdministratorAccess",
                    PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
                )
            ],
        )
        resolver = PolicyResolver(make_snapshot(roles=[role], policies=[policy]))
        result = resolver.resolve_role(role)

        assert result.can("iam:CreateRole") is True
        assert result.can("s3:DeleteBucket") is True
        assert result.identity_type == IdentityType.ROLE

    def test_role_with_no_policies(self) -> None:
        role = IAMRole(
            name="empty-role",
            arn="arn:aws:iam::123:role/empty-role",
            role_id="RID2",
            trust_policy=make_trust_doc(),
        )
        resolver = PolicyResolver(make_snapshot(roles=[role]))
        result = resolver.resolve_role(role)

        assert result.effective_permissions == []


# ---------------------------------------------------------------------------
# Tests: resolve_all
# ---------------------------------------------------------------------------

class TestResolveAll:

    def test_resolve_all_returns_entry_per_identity(self) -> None:
        user = IAMUser(
            name="alice",
            arn="arn:aws:iam::123:user/alice",
            user_id="U1",
        )
        role = IAMRole(
            name="my-role",
            arn="arn:aws:iam::123:role/my-role",
            role_id="R1",
            trust_policy=make_trust_doc(),
        )
        resolver = PolicyResolver(make_snapshot(users=[user], roles=[role]))
        all_resolved = resolver.resolve_all()

        assert "arn:aws:iam::123:user/alice" in all_resolved
        assert "arn:aws:iam::123:role/my-role" in all_resolved
        assert len(all_resolved) == 2
