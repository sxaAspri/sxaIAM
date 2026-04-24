"""
Tests for sxaiam.findings.techniques

Verifies that each technique correctly detects the attack patterns
that exist in our Terraform sandbox environment.
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
from sxaiam.findings.technique_base import Severity
from sxaiam.findings.techniques import (
    ALL_TECHNIQUES,
    AssumeRoleChainTechnique,
    AttachPolicyTechnique,
    CreateAccessKeyTechnique,
    CreatePolicyVersionTechnique,
    PassRoleLambdaTechnique,
)
from sxaiam.resolver.engine import PolicyResolver
from sxaiam.resolver.models import IdentityType, ResolvedIdentity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_doc(actions: list[str], resources: list[str],
             effect: str = "Allow") -> PolicyDocument:
    return PolicyDocument.from_raw({
        "Version": "2012-10-17",
        "Statement": [{"Effect": effect, "Action": actions, "Resource": resources}],
    })


def make_trust_doc(service: str = "lambda.amazonaws.com") -> PolicyDocument:
    return PolicyDocument.from_raw({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": service},
            "Action": "sts:AssumeRole",
        }],
    })


def make_role_trust_doc(principal_arn: str) -> PolicyDocument:
    return PolicyDocument.from_raw({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": principal_arn},
            "Action": "sts:AssumeRole",
        }],
    })


def make_policy(name: str, arn: str, *actions: str) -> IAMPolicy:
    return IAMPolicy(
        name=name, arn=arn, policy_id=f"ID-{name}",
        is_aws_managed=arn.startswith("arn:aws:iam::aws:"),
        document=make_doc(list(actions), ["*"]),
    )


def make_snapshot(**kwargs: object) -> IAMSnapshot:
    s = IAMSnapshot(
        account_id="123456789012",
        users=kwargs.get("users", []),  # type: ignore[arg-type]
        roles=kwargs.get("roles", []),  # type: ignore[arg-type]
        policies=kwargs.get("policies", []),  # type: ignore[arg-type]
    )
    s.build_indexes()
    return s


def resolve_user(user: IAMUser, snapshot: IAMSnapshot) -> ResolvedIdentity:
    return PolicyResolver(snapshot).resolve_user(user)


def resolve_role(role: IAMRole, snapshot: IAMSnapshot) -> ResolvedIdentity:
    return PolicyResolver(snapshot).resolve_role(role)


# ---------------------------------------------------------------------------
# Technique 1 — CreatePolicyVersion
# ---------------------------------------------------------------------------

class TestCreatePolicyVersion:

    def _setup(self) -> tuple[IAMUser, IAMPolicy, IAMSnapshot]:
        policy = IAMPolicy(
            name="DeploymentPolicy",
            arn="arn:aws:iam::123:policy/DeploymentPolicy",
            policy_id="PID1",
            is_aws_managed=False,
            document=make_doc(["ec2:DescribeInstances"], ["*"]),
        )
        perm_policy = make_policy(
            "LowPrivPerms",
            "arn:aws:iam::123:policy/LowPrivPerms",
            "iam:CreatePolicyVersion",
            "iam:SetDefaultPolicyVersion",
        )
        user = IAMUser(
            name="low-priv-user",
            arn="arn:aws:iam::123:user/low-priv-user",
            user_id="UID1",
            attached_policies=[
                AttachedPolicy(
                    PolicyName="LowPrivPerms",
                    PolicyArn="arn:aws:iam::123:policy/LowPrivPerms",
                ),
                AttachedPolicy(
                    PolicyName="DeploymentPolicy",
                    PolicyArn="arn:aws:iam::123:policy/DeploymentPolicy",
                ),
            ],
        )
        snapshot = make_snapshot(
            users=[user], policies=[policy, perm_policy]
        )
        return user, policy, snapshot

    def test_detects_create_policy_version_attack(self) -> None:
        user, policy, snapshot = self._setup()
        identity = resolve_user(user, snapshot)
        technique = CreatePolicyVersionTechnique()
        matches = technique.check(identity, snapshot)

        assert len(matches) >= 1
        assert any(m.target_arn == policy.arn for m in matches)
        assert matches[0].severity == Severity.CRITICAL

    def test_no_match_when_policy_not_attached_to_self(self) -> None:
        policy = IAMPolicy(
            name="OtherPolicy",
            arn="arn:aws:iam::123:policy/OtherPolicy",
            policy_id="PID2",
            is_aws_managed=False,
            document=make_doc(["ec2:*"], ["*"]),
        )
        perm_policy = make_policy(
            "Perms", "arn:aws:iam::123:policy/Perms",
            "iam:CreatePolicyVersion",
        )
        user = IAMUser(
            name="user",
            arn="arn:aws:iam::123:user/user",
            user_id="UID2",
            attached_policies=[
                AttachedPolicy(PolicyName="Perms",
                               PolicyArn="arn:aws:iam::123:policy/Perms"),
            ],
        )
        snapshot = make_snapshot(users=[user], policies=[policy, perm_policy])
        identity = resolve_user(user, snapshot)
        technique = CreatePolicyVersionTechnique()
        matches = technique.check(identity, snapshot)

        assert len(matches) == 1
        assert matches[0].target_arn == "arn:aws:iam::123:policy/Perms"

    def test_evidence_contains_permission_info(self) -> None:
        user, _, snapshot = self._setup()
        identity = resolve_user(user, snapshot)
        matches = CreatePolicyVersionTechnique().check(identity, snapshot)
        assert any("iam:CreatePolicyVersion" in ev for ev in matches[0].evidence)


# ---------------------------------------------------------------------------
# Technique 2 — PassRole + Lambda
# ---------------------------------------------------------------------------

class TestPassRoleLambda:

    def _setup(self) -> tuple[IAMUser, IAMRole, IAMSnapshot]:
        admin_role = IAMRole(
            name="admin-role",
            arn="arn:aws:iam::123:role/admin-role",
            role_id="RID1",
            trust_policy=make_trust_doc("lambda.amazonaws.com"),
            attached_policies=[
                AttachedPolicy(
                    PolicyName="AdministratorAccess",
                    PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
                )
            ],
        )
        dev_policy = make_policy(
            "DevPerms", "arn:aws:iam::123:policy/DevPerms",
            "iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction",
        )
        user = IAMUser(
            name="developer-user",
            arn="arn:aws:iam::123:user/developer-user",
            user_id="UID3",
            attached_policies=[
                AttachedPolicy(PolicyName="DevPerms",
                               PolicyArn="arn:aws:iam::123:policy/DevPerms"),
            ],
        )
        snapshot = make_snapshot(users=[user], roles=[admin_role],
                                 policies=[dev_policy])
        return user, admin_role, snapshot

    def test_detects_passrole_lambda_attack(self) -> None:
        user, admin_role, snapshot = self._setup()
        identity = resolve_user(user, snapshot)
        matches = PassRoleLambdaTechnique().check(identity, snapshot)

        assert len(matches) >= 1
        target_arns = [m.target_arn for m in matches]
        assert admin_role.arn in target_arns

    def test_no_match_without_lambda_create(self) -> None:
        admin_role = IAMRole(
            name="admin-role",
            arn="arn:aws:iam::123:role/admin-role",
            role_id="RID2",
            trust_policy=make_trust_doc(),
            attached_policies=[AttachedPolicy(
                PolicyName="AdministratorAccess",
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            )],
        )
        policy = make_policy(
            "OnlyPassRole", "arn:aws:iam::123:policy/OnlyPassRole",
            "iam:PassRole",
        )
        user = IAMUser(
            name="user",
            arn="arn:aws:iam::123:user/user",
            user_id="UID4",
            attached_policies=[AttachedPolicy(
                PolicyName="OnlyPassRole",
                PolicyArn="arn:aws:iam::123:policy/OnlyPassRole",
            )],
        )
        snapshot = make_snapshot(users=[user], roles=[admin_role],
                                 policies=[policy])
        identity = resolve_user(user, snapshot)
        matches = PassRoleLambdaTechnique().check(identity, snapshot)
        assert len(matches) == 0

    def test_attack_steps_mention_lambda(self) -> None:
        user, _, snapshot = self._setup()
        identity = resolve_user(user, snapshot)
        matches = PassRoleLambdaTechnique().check(identity, snapshot)
        steps_text = " ".join(matches[0].attack_steps)
        assert "lambda" in steps_text.lower()


# ---------------------------------------------------------------------------
# Technique 3 — AssumeRole chain
# ---------------------------------------------------------------------------

class TestAssumeRoleChain:

    def test_detects_assumerole_chain(self) -> None:
        admin_role = IAMRole(
            name="admin-role",
            arn="arn:aws:iam::123:role/admin-role",
            role_id="RID3",
            trust_policy=make_trust_doc(),
            attached_policies=[AttachedPolicy(
                PolicyName="AdministratorAccess",
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            )],
        )
        ci_policy = make_policy(
            "CIPerms", "arn:aws:iam::123:policy/CIPerms",
            "sts:AssumeRole",
        )
        ci_role = IAMRole(
            name="ci-role",
            arn="arn:aws:iam::123:role/ci-role",
            role_id="RID4",
            trust_policy=make_trust_doc("ec2.amazonaws.com"),
            attached_policies=[AttachedPolicy(
                PolicyName="CIPerms",
                PolicyArn="arn:aws:iam::123:policy/CIPerms",
            )],
        )
        snapshot = make_snapshot(
            roles=[ci_role, admin_role], policies=[ci_policy]
        )
        identity = resolve_role(ci_role, snapshot)
        matches = AssumeRoleChainTechnique().check(identity, snapshot)

        assert len(matches) >= 1
        assert any(m.target_arn == admin_role.arn for m in matches)

    def test_no_match_without_assumerole_permission(self) -> None:
        admin_role = IAMRole(
            name="admin-role",
            arn="arn:aws:iam::123:role/admin-role",
            role_id="RID5",
            trust_policy=make_trust_doc(),
            attached_policies=[AttachedPolicy(
                PolicyName="AdministratorAccess",
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            )],
        )
        ci_policy = make_policy(
            "CIPerms", "arn:aws:iam::123:policy/CIPerms",
            "s3:GetObject",
        )
        ci_role = IAMRole(
            name="ci-role",
            arn="arn:aws:iam::123:role/ci-role",
            role_id="RID6",
            trust_policy=make_trust_doc("ec2.amazonaws.com"),
            attached_policies=[AttachedPolicy(
                PolicyName="CIPerms",
                PolicyArn="arn:aws:iam::123:policy/CIPerms",
            )],
        )
        snapshot = make_snapshot(roles=[ci_role, admin_role], policies=[ci_policy])
        identity = resolve_role(ci_role, snapshot)
        matches = AssumeRoleChainTechnique().check(identity, snapshot)
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# Technique 4 — AttachUserPolicy
# ---------------------------------------------------------------------------

class TestAttachPolicy:

    def test_detects_attach_user_policy(self) -> None:
        policy = make_policy(
            "ReadonlyPerms", "arn:aws:iam::123:policy/ReadonlyPerms",
            "iam:AttachUserPolicy",
        )
        user = IAMUser(
            name="readonly-user",
            arn="arn:aws:iam::123:user/readonly-user",
            user_id="UID5",
            attached_policies=[AttachedPolicy(
                PolicyName="ReadonlyPerms",
                PolicyArn="arn:aws:iam::123:policy/ReadonlyPerms",
            )],
        )
        snapshot = make_snapshot(users=[user], policies=[policy])
        identity = resolve_user(user, snapshot)
        matches = AttachPolicyTechnique().check(identity, snapshot)

        assert len(matches) >= 1
        assert matches[0].severity == Severity.CRITICAL

    def test_no_match_without_attach_permission(self) -> None:
        policy = make_policy(
            "SafePerms", "arn:aws:iam::123:policy/SafePerms",
            "s3:GetObject",
        )
        user = IAMUser(
            name="safe-user",
            arn="arn:aws:iam::123:user/safe-user",
            user_id="UID6",
            attached_policies=[AttachedPolicy(
                PolicyName="SafePerms",
                PolicyArn="arn:aws:iam::123:policy/SafePerms",
            )],
        )
        snapshot = make_snapshot(users=[user], policies=[policy])
        identity = resolve_user(user, snapshot)
        matches = AttachPolicyTechnique().check(identity, snapshot)
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# Technique 5 — CreateAccessKey
# ---------------------------------------------------------------------------

class TestCreateAccessKey:

    def test_detects_credential_takeover(self) -> None:
        priv_policy = make_policy(
            "PowerUser", "arn:aws:iam::aws:policy/PowerUserAccess", "s3:*"
        )
        privileged_user = IAMUser(
            name="privileged-user",
            arn="arn:aws:iam::123:user/privileged-user",
            user_id="UID7",
            attached_policies=[AttachedPolicy(
                PolicyName="PowerUserAccess",
                PolicyArn="arn:aws:iam::aws:policy/PowerUserAccess",
            )],
        )
        support_policy = IAMPolicy(
            name="SupportPerms",
            arn="arn:aws:iam::123:policy/SupportPerms",
            policy_id="PID3",
            is_aws_managed=False,
            document=make_doc(
                ["iam:CreateAccessKey"],
                [privileged_user.arn],
            ),
        )
        support_user = IAMUser(
            name="support-user",
            arn="arn:aws:iam::123:user/support-user",
            user_id="UID8",
            attached_policies=[AttachedPolicy(
                PolicyName="SupportPerms",
                PolicyArn="arn:aws:iam::123:policy/SupportPerms",
            )],
        )
        snapshot = make_snapshot(
            users=[support_user, privileged_user],
            policies=[support_policy, priv_policy],
        )
        identity = resolve_user(support_user, snapshot)
        matches = CreateAccessKeyTechnique().check(identity, snapshot)

        assert len(matches) == 1
        assert matches[0].target_arn == privileged_user.arn
        assert matches[0].origin_name == "support-user"

    def test_no_match_on_self(self) -> None:
        policy = make_policy(
            "SelfKey", "arn:aws:iam::123:policy/SelfKey",
            "iam:CreateAccessKey",
        )
        user = IAMUser(
            name="user",
            arn="arn:aws:iam::123:user/user",
            user_id="UID9",
            attached_policies=[AttachedPolicy(
                PolicyName="SelfKey",
                PolicyArn="arn:aws:iam::123:policy/SelfKey",
            )],
        )
        snapshot = make_snapshot(users=[user], policies=[policy])
        identity = resolve_user(user, snapshot)
        matches = CreateAccessKeyTechnique().check(identity, snapshot)
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# ALL_TECHNIQUES registry
# ---------------------------------------------------------------------------

class TestAllTechniques:

    def test_registry_has_five_techniques(self) -> None:
        assert len(ALL_TECHNIQUES) == 5

    def test_all_techniques_have_unique_ids(self) -> None:
        ids = [t.technique_id for t in ALL_TECHNIQUES]
        assert len(ids) == len(set(ids))

    def test_all_techniques_have_required_actions(self) -> None:
        for technique_cls in ALL_TECHNIQUES:
            technique = technique_cls()
            assert len(technique.required_actions) > 0

    def test_all_techniques_have_description(self) -> None:
        for technique_cls in ALL_TECHNIQUES:
            technique = technique_cls()
            assert len(technique.description) > 20
