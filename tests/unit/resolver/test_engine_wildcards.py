"""
Tests for PolicyResolver — layers 2 and 3: wildcard resolution.

Layer 2: wildcard actions  (iam:*, s3:Get*, *)
Layer 3: wildcard resources (arn:aws:iam::*:role/*, *)

These tests verify that the resolver correctly handles the most common
real-world IAM patterns — the ones that actually create attack paths.
"""

import pytest
from sxaiam.ingestion.models import (
    AttachedPolicy,
    IAMPolicy,
    IAMRole,
    IAMSnapshot,
    IAMUser,
    PolicyDocument,
)
from sxaiam.resolver.engine import PolicyResolver


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_policy_doc(
    actions: list[str],
    resources: list[str],
    effect: str = "Allow",
) -> PolicyDocument:
    return PolicyDocument.from_raw({
        "Version": "2012-10-17",
        "Statement": [{"Effect": effect, "Action": actions, "Resource": resources}],
    })


def make_managed_policy(name: str, arn: str, doc: PolicyDocument) -> IAMPolicy:
    return IAMPolicy(
        name=name, arn=arn, policy_id=f"ID-{name}",
        is_aws_managed=False, document=doc,
    )


def make_trust_doc() -> PolicyDocument:
    return PolicyDocument.from_raw({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    })


def make_snapshot(users=None, roles=None, policies=None) -> IAMSnapshot:
    s = IAMSnapshot(
        account_id="123456789012",
        users=users or [], roles=roles or [], policies=policies or [],
    )
    s.build_indexes()
    return s


def make_user_with_inline(name: str, doc: PolicyDocument) -> IAMUser:
    return IAMUser(
        name=name,
        arn=f"arn:aws:iam::123:user/{name}",
        user_id=f"UID-{name}",
        inline_policies={"TestPolicy": doc},
    )


# ---------------------------------------------------------------------------
# Layer 2 — wildcard actions
# ---------------------------------------------------------------------------

class TestLayer2WildcardActions:

    def test_iam_star_covers_create_policy_version(self) -> None:
        """
        Real attack path 1: user has iam:* → can do iam:CreatePolicyVersion
        """
        user = make_user_with_inline(
            "low-priv",
            make_policy_doc(["iam:*"], ["*"]),
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.can("iam:CreatePolicyVersion") is True
        assert result.can("iam:AttachUserPolicy") is True
        assert result.can("iam:CreateAccessKey") is True

    def test_iam_star_does_not_cover_s3(self) -> None:
        user = make_user_with_inline(
            "user",
            make_policy_doc(["iam:*"], ["*"]),
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.can("s3:GetObject") is False

    def test_star_action_covers_everything(self) -> None:
        """
        AdministratorAccess uses Action: * — should cover any action.
        """
        policy = make_managed_policy(
            "AdministratorAccess",
            "arn:aws:iam::aws:policy/AdministratorAccess",
            make_policy_doc(["*"], ["*"]),
        )
        role = IAMRole(
            name="admin-role",
            arn="arn:aws:iam::123:role/admin-role",
            role_id="RID1",
            trust_policy=make_trust_doc(),
            attached_policies=[AttachedPolicy(
                PolicyName="AdministratorAccess",
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            )],
        )
        resolver = PolicyResolver(make_snapshot(roles=[role], policies=[policy]))
        result = resolver.resolve_role(role)

        assert result.can("iam:CreateRole") is True
        assert result.can("s3:DeleteBucket") is True
        assert result.can("lambda:InvokeFunction") is True
        assert result.can("sts:AssumeRole") is True

    def test_prefix_wildcard_s3_get_star(self) -> None:
        user = make_user_with_inline(
            "reader",
            make_policy_doc(["s3:Get*", "s3:List*"], ["*"]),
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.can("s3:GetObject") is True
        assert result.can("s3:GetBucketPolicy") is True
        assert result.can("s3:ListBucket") is True
        assert result.can("s3:PutObject") is False
        assert result.can("s3:DeleteObject") is False

    def test_deny_with_wildcard_removes_all_matching_allows(self) -> None:
        """
        Deny iam:* removes ALL iam: actions even if individually allowed.
        """
        user = IAMUser(
            name="restricted",
            arn="arn:aws:iam::123:user/restricted",
            user_id="UID-R",
            inline_policies={
                "AllowIAM": make_policy_doc(
                    ["iam:CreateRole", "iam:PassRole", "iam:AttachUserPolicy"], ["*"]
                ),
                "DenyAllIAM": make_policy_doc(["iam:*"], ["*"], effect="Deny"),
            },
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.can("iam:CreateRole") is False
        assert result.can("iam:PassRole") is False
        assert result.can("iam:AttachUserPolicy") is False


# ---------------------------------------------------------------------------
# Layer 3 — wildcard resources
# ---------------------------------------------------------------------------

class TestLayer3WildcardResources:

    ADMIN_ROLE_ARN = "arn:aws:iam::123:role/admin-role"
    OTHER_ROLE_ARN = "arn:aws:iam::123:role/readonly-role"
    USER_ARN       = "arn:aws:iam::123:user/alice"

    def test_star_resource_covers_any_arn(self) -> None:
        user = make_user_with_inline(
            "dev",
            make_policy_doc(["iam:PassRole"], ["*"]),
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.can("iam:PassRole", self.ADMIN_ROLE_ARN) is True
        assert result.can("iam:PassRole", self.OTHER_ROLE_ARN) is True

    def test_specific_resource_arn_only_covers_that_arn(self) -> None:
        user = make_user_with_inline(
            "dev",
            make_policy_doc(["iam:PassRole"], [self.ADMIN_ROLE_ARN]),
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.can("iam:PassRole", self.ADMIN_ROLE_ARN) is True
        assert result.can("iam:PassRole", self.OTHER_ROLE_ARN) is False

    def test_prefix_wildcard_resource_covers_matching_arns(self) -> None:
        """
        arn:aws:iam::123:role/* covers all roles but not users.
        This is the real pattern used in PassRole attack paths.
        """
        user = make_user_with_inline(
            "dev",
            make_policy_doc(["iam:PassRole"], ["arn:aws:iam::123:role/*"]),
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.can("iam:PassRole", self.ADMIN_ROLE_ARN) is True
        assert result.can("iam:PassRole", self.OTHER_ROLE_ARN) is True
        assert result.can("iam:PassRole", self.USER_ARN) is False

    def test_cross_account_wildcard_resource(self) -> None:
        """
        arn:aws:iam::*:role/admin covers the same role in any account.
        """
        user = make_user_with_inline(
            "dev",
            make_policy_doc(["sts:AssumeRole"], ["arn:aws:iam::*:role/admin"]),
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.can("sts:AssumeRole", "arn:aws:iam::999:role/admin") is True
        assert result.can("sts:AssumeRole", "arn:aws:iam::123:role/admin") is True
        assert result.can("sts:AssumeRole", "arn:aws:iam::999:role/other") is False

    def test_deny_on_specific_resource_does_not_affect_others(self) -> None:
        """
        Deny on one specific ARN should not block access to other ARNs.
        """
        user = IAMUser(
            name="partial",
            arn="arn:aws:iam::123:user/partial",
            user_id="UID-P",
            inline_policies={
                "AllowPassRole": make_policy_doc(["iam:PassRole"], ["*"]),
                "DenyAdminRole": make_policy_doc(
                    ["iam:PassRole"], [self.ADMIN_ROLE_ARN], effect="Deny"
                ),
            },
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.can("iam:PassRole", self.ADMIN_ROLE_ARN) is False
        assert result.can("iam:PassRole", self.OTHER_ROLE_ARN) is True


# ---------------------------------------------------------------------------
# Combined layers 2 + 3 — real attack path patterns
# ---------------------------------------------------------------------------

class TestRealAttackPatterns:

    def test_passrole_lambda_pattern(self) -> None:
        """
        Path 2 in our sandbox: developer_user has PassRole + lambda:CreateFunction.
        Both permissions need wildcard-aware resolution to be detected.
        """
        user = make_user_with_inline(
            "developer",
            make_policy_doc(
                ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
                ["*"],
            ),
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        admin_role = "arn:aws:iam::123:role/admin-role"
        assert result.can("iam:PassRole", admin_role) is True
        assert result.can("lambda:CreateFunction") is True
        assert result.can("lambda:InvokeFunction") is True

    def test_attach_policy_pattern(self) -> None:
        """
        Path 4: readonly_user has iam:AttachUserPolicy on * → can attach admin.
        """
        user = make_user_with_inline(
            "readonly",
            make_policy_doc(["iam:AttachUserPolicy"], ["*"]),
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.can("iam:AttachUserPolicy", "*") is True
        assert result.can(
            "iam:AttachUserPolicy",
            "arn:aws:iam::123:user/readonly",
        ) is True

    def test_create_access_key_pattern(self) -> None:
        """
        Path 5: support_user has iam:CreateAccessKey on specific privileged_user ARN.
        """
        privileged_arn = "arn:aws:iam::123:user/privileged-user"
        user = make_user_with_inline(
            "support",
            make_policy_doc(["iam:CreateAccessKey"], [privileged_arn]),
        )
        resolver = PolicyResolver(make_snapshot(users=[user]))
        result = resolver.resolve_user(user)

        assert result.can("iam:CreateAccessKey", privileged_arn) is True
        assert result.can(
            "iam:CreateAccessKey",
            "arn:aws:iam::123:user/other-user",
        ) is False
