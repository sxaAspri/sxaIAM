"""
tests/integration/test_full_analysis.py

Integration test for the current end-to-end analysis pipeline.

Pipeline under test:
  IAMSnapshot -> PolicyResolver -> AttackGraph -> PathFinder -> EscalationPaths

The handcrafted snapshot mirrors the current Terraform sandbox coverage:
  path1: low_priv_user         with iam:CreatePolicyVersion       -> CRITICAL
  path2: developer_user        with iam:PassRole + Lambda         -> HIGH
  path3: ci_role               with sts:AssumeRole chain          -> HIGH
  path4: readonly_user         with iam:AttachUserPolicy          -> CRITICAL
  path5: support_user          with iam:CreateAccessKey           -> HIGH
  path6: helpdesk_user         with iam:CreateLoginProfile        -> HIGH
  path7: password_reset_user   with iam:UpdateLoginProfile        -> HIGH
  path8: policy_manager_user   with iam:SetDefaultPolicyVersion   -> HIGH
  path9: contractor_user       with iam:AddUserToGroup            -> HIGH

Success criteria:
  - 9/9 escalation techniques are detected in the pipeline output
  - Every path contains at least one explicit evidence-bearing step
  - Every evidence item references the concrete IAM action that justifies it
  - CRITICAL paths are ordered before HIGH paths in the final output

No AWS credentials or moto are used here. The snapshot is built by hand to
exercise the same module boundaries and data flow as a real account scan.
"""

from __future__ import annotations

import pytest

from sxaiam.findings.technique_base import Severity
from sxaiam.graph.builder import AttackGraph
from sxaiam.graph.pathfinder import PathFinder
from sxaiam.ingestion.models import (
    AttachedPolicy,
    IAMGroup,
    IAMPolicy,
    IAMRole,
    IAMSnapshot,
    IAMUser,
    PolicyDocument,
    PolicyStatement,
)
from sxaiam.resolver.engine import PolicyResolver
from sxaiam.resolver.models import ResolvedIdentity


# ---------------------------------------------------------------------------
# Sandbox constants
# ---------------------------------------------------------------------------

ACCOUNT_ID = "123456789012"
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
POWERUSER_POLICY_ARN = "arn:aws:iam::aws:policy/PowerUserAccess"

# User ARNs
LOW_PRIV_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/low_priv_user"
DEV_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/developer_user"
READONLY_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/readonly_user"
SUPPORT_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/support_user"
PRIV_USER_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/privileged_user"
HELPDESK_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/helpdesk_user"
CONSOLE_ADMIN_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/console_admin_user"
PASSWORD_RESET_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/password_reset_user"
FINANCE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/finance_user"
POLICY_MANAGER_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/policy_manager_user"
CONTRACTOR_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/contractor_user"

# Role ARNs
CI_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/ci_role"
ADMIN_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/admin_role"
LAMBDA_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/lambda_exec_role"

# Group ARNs
ADMIN_GROUP_ARN = f"arn:aws:iam::{ACCOUNT_ID}:group/admin_group"


# ---------------------------------------------------------------------------
# Snapshot helpers
# ---------------------------------------------------------------------------

def _stmt(effect: str, actions: list[str], resources: list[str]) -> PolicyStatement:
    return PolicyStatement(
        Effect=effect,
        actions=actions,
        resources=resources,
        principal=None,
    )


def _inline_doc(actions: list[str], resources: list[str] | None = None) -> PolicyDocument:
    return PolicyDocument(
        statements=[_stmt("Allow", actions, resources or ["*"])]
    )


def _trust_doc(principals: list[str] | None = None, services: list[str] | None = None) -> PolicyDocument:
    principal: dict[str, object] = {}
    if principals:
        principal["AWS"] = principals
    if services:
        principal["Service"] = services if len(services) > 1 else services[0]

    return PolicyDocument(
        statements=[
            PolicyStatement(
                Effect="Allow",
                actions=["sts:AssumeRole"],
                resources=["*"],
                principal=principal,
            )
        ]
    )


def _attached(policy_name: str, policy_arn: str) -> AttachedPolicy:
    return AttachedPolicy(PolicyName=policy_name, PolicyArn=policy_arn)


def _make_user(
    arn: str,
    name: str,
    inline_actions: list[str] | None = None,
    attached_policies: list[AttachedPolicy] | None = None,
    group_names: list[str] | None = None,
) -> IAMUser:
    return IAMUser(
        arn=arn,
        name=name,
        user_id=f"AIDA{name.upper()[:12]}",
        path="/",
        inline_policies=(
            {"sandbox-policy": _inline_doc(inline_actions)}
            if inline_actions else {}
        ),
        attached_policies=attached_policies or [],
        group_names=group_names or [],
    )


def _make_role(
    arn: str,
    name: str,
    inline_actions: list[str] | None = None,
    attached_policies: list[AttachedPolicy] | None = None,
    trust_principals: list[str] | None = None,
    trust_services: list[str] | None = None,
) -> IAMRole:
    return IAMRole(
        arn=arn,
        name=name,
        role_id=f"AROA{name.upper()[:12]}",
        path="/",
        trust_policy=_trust_doc(trust_principals, trust_services),
        inline_policies=(
            {"sandbox-policy": _inline_doc(inline_actions)}
            if inline_actions else {}
        ),
        attached_policies=attached_policies or [],
    )


# ---------------------------------------------------------------------------
# Main snapshot fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sandbox_snapshot() -> IAMSnapshot:
    # Managed policies referenced by vulnerable identities
    deployment_policy = IAMPolicy(
        name="DeploymentPolicy",
        arn=f"arn:aws:iam::{ACCOUNT_ID}:policy/DeploymentPolicy",
        policy_id="PID-DEPLOY",
        is_aws_managed=False,
        document=_inline_doc(["ec2:DescribeInstances"]),
    )
    policy_manager_policy = IAMPolicy(
        name="PolicyManagerPolicy",
        arn=f"arn:aws:iam::{ACCOUNT_ID}:policy/PolicyManagerPolicy",
        policy_id="PID-MANAGER",
        is_aws_managed=False,
        document=_inline_doc(
            ["iam:SetDefaultPolicyVersion", "iam:ListPolicyVersions"],
            [f"arn:aws:iam::{ACCOUNT_ID}:policy/DeploymentPolicy"],
        ),
    )
    support_policy = IAMPolicy(
        name="SupportTakeoverPolicy",
        arn=f"arn:aws:iam::{ACCOUNT_ID}:policy/SupportTakeoverPolicy",
        policy_id="PID-SUPPORT",
        is_aws_managed=False,
        document=_inline_doc(["iam:CreateAccessKey"], [PRIV_USER_ARN]),
    )
    helpdesk_policy = IAMPolicy(
        name="HelpdeskConsolePolicy",
        arn=f"arn:aws:iam::{ACCOUNT_ID}:policy/HelpdeskConsolePolicy",
        policy_id="PID-HELPDESK",
        is_aws_managed=False,
        document=_inline_doc(["iam:CreateLoginProfile"], [CONSOLE_ADMIN_ARN]),
    )
    password_reset_policy = IAMPolicy(
        name="PasswordResetPolicy",
        arn=f"arn:aws:iam::{ACCOUNT_ID}:policy/PasswordResetPolicy",
        policy_id="PID-PASSWORD",
        is_aws_managed=False,
        document=_inline_doc(["iam:UpdateLoginProfile"], [FINANCE_ARN]),
    )
    contractor_policy = IAMPolicy(
        name="ContractorGroupPolicy",
        arn=f"arn:aws:iam::{ACCOUNT_ID}:policy/ContractorGroupPolicy",
        policy_id="PID-CONTRACTOR",
        is_aws_managed=False,
        document=_inline_doc(["iam:AddUserToGroup"], [ADMIN_GROUP_ARN]),
    )

    low_priv = IAMUser(
        arn=LOW_PRIV_ARN,
        name="low_priv_user",
        user_id="AIDALOWPRIV",
        path="/",
        inline_policies={"sandbox-policy": _inline_doc([
            "iam:CreatePolicyVersion",
            "iam:SetDefaultPolicyVersion",
        ])},
        attached_policies=[_attached("DeploymentPolicy", deployment_policy.arn)],
        group_names=[],
    )

    developer = _make_user(
        DEV_ARN,
        "developer_user",
        inline_actions=[
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
        ],
    )
    readonly = _make_user(READONLY_ARN, "readonly_user", inline_actions=["iam:AttachUserPolicy"])
    support = _make_user(
        SUPPORT_ARN,
        "support_user",
        attached_policies=[_attached("SupportTakeoverPolicy", support_policy.arn)],
    )
    privileged = _make_user(PRIV_USER_ARN, "privileged_user", inline_actions=["*"])
    helpdesk = _make_user(
        HELPDESK_ARN,
        "helpdesk_user",
        attached_policies=[_attached("HelpdeskConsolePolicy", helpdesk_policy.arn)],
    )
    console_admin = _make_user(
        CONSOLE_ADMIN_ARN,
        "console_admin_user",
        attached_policies=[_attached("AdministratorAccess", ADMIN_POLICY_ARN)],
    )
    password_reset = _make_user(
        PASSWORD_RESET_ARN,
        "password_reset_user",
        attached_policies=[_attached("PasswordResetPolicy", password_reset_policy.arn)],
    )
    finance_user = _make_user(
        FINANCE_ARN,
        "finance_user",
        attached_policies=[_attached("PowerUserAccess", POWERUSER_POLICY_ARN)],
    )
    policy_manager = _make_user(
        POLICY_MANAGER_ARN,
        "policy_manager_user",
        attached_policies=[
            _attached("DeploymentPolicy", deployment_policy.arn),
            _attached("PolicyManagerPolicy", policy_manager_policy.arn),
        ],
    )
    contractor = _make_user(
        CONTRACTOR_ARN,
        "contractor_user",
        attached_policies=[_attached("ContractorGroupPolicy", contractor_policy.arn)],
    )

    ci_role = _make_role(
        CI_ROLE_ARN,
        "ci_role",
        inline_actions=["sts:AssumeRole"],
        trust_principals=[DEV_ARN],
    )
    admin_role = _make_role(
        ADMIN_ROLE_ARN,
        "admin_role",
        inline_actions=["*"],
        trust_principals=[CI_ROLE_ARN],
    )
    lambda_role = _make_role(
        LAMBDA_ROLE_ARN,
        "lambda_exec_role",
        inline_actions=["s3:GetObject"],
        attached_policies=[_attached("PowerUserAccess", POWERUSER_POLICY_ARN)],
        trust_services=["lambda.amazonaws.com"],
    )

    admin_group = IAMGroup(
        name="admin_group",
        arn=ADMIN_GROUP_ARN,
        group_id="GIDADMIN",
        path="/",
        attached_policies=[_attached("AdministratorAccess", ADMIN_POLICY_ARN)],
        inline_policy_names=[],
        inline_policies={},
        member_names=[],
    )

    snapshot = IAMSnapshot(
        account_id=ACCOUNT_ID,
        users=[
            low_priv,
            developer,
            readonly,
            support,
            privileged,
            helpdesk,
            console_admin,
            password_reset,
            finance_user,
            policy_manager,
            contractor,
        ],
        roles=[ci_role, admin_role, lambda_role],
        groups=[admin_group],
        policies=[
            deployment_policy,
            policy_manager_policy,
            support_policy,
            helpdesk_policy,
            password_reset_policy,
            contractor_policy,
        ],
    )
    snapshot.build_indexes()
    return snapshot


@pytest.fixture(scope="module")
def resolved_identities(sandbox_snapshot: IAMSnapshot) -> list[ResolvedIdentity]:
    """Resolve effective permissions for all identities in the snapshot."""
    resolver = PolicyResolver(sandbox_snapshot)
    return list(resolver.resolve_all().values())


@pytest.fixture(scope="module")
def escalation_paths(
    sandbox_snapshot: IAMSnapshot,
    resolved_identities: list[ResolvedIdentity],
) -> list:
    """Run the full pipeline and return all detected escalation paths."""
    graph = AttackGraph()
    G = graph.build(sandbox_snapshot, resolved_identities)
    finder = PathFinder(G)
    return finder.find_all_paths()


# ---------------------------------------------------------------------------
# Tests - 9/9 techniques detected
# ---------------------------------------------------------------------------

class TestNinePathsDetected:
    """Verify the snapshot yields the full current technique set."""

    EXPECTED_TECHNIQUES = {
        "create-policy-version",
        "passrole-lambda",
        "assumerole-chain",
        "attach-policy",
        "create-access-key",
        "create-login-profile",
        "update-login-profile",
        "set-default-policy-version",
        "add-user-to-group",
    }

    def _get_techniques(self, paths: list) -> set[str]:
        techniques = set()
        for path in paths:
            for step in path.steps:
                if step.technique_id != "trust_policy":
                    techniques.add(step.technique_id)
        return techniques

    def test_at_least_nine_paths_found(self, escalation_paths: list):
        assert len(escalation_paths) >= 9, (
            f"Expected at least 9 escalation paths, found {len(escalation_paths)}"
        )

    def test_all_expected_techniques_detected(self, escalation_paths: list):
        techniques = self._get_techniques(escalation_paths)
        assert self.EXPECTED_TECHNIQUES.issubset(techniques), (
            f"Missing techniques: {self.EXPECTED_TECHNIQUES - techniques}. "
            f"Detected: {techniques}"
        )

    @pytest.mark.parametrize(
        ("origin_arn", "name"),
        [
            (LOW_PRIV_ARN, "low_priv_user"),
            (DEV_ARN, "developer_user"),
            (READONLY_ARN, "readonly_user"),
            (SUPPORT_ARN, "support_user"),
            (HELPDESK_ARN, "helpdesk_user"),
            (PASSWORD_RESET_ARN, "password_reset_user"),
            (POLICY_MANAGER_ARN, "policy_manager_user"),
            (CONTRACTOR_ARN, "contractor_user"),
            (CI_ROLE_ARN, "ci_role"),
        ],
    )
    def test_expected_identity_has_path(self, escalation_paths: list, origin_arn: str, name: str):
        matching_paths = [p for p in escalation_paths if p.origin_arn == origin_arn]
        assert matching_paths, f"{name} should have at least one escalation path"


# ---------------------------------------------------------------------------
# Tests - explicit evidence on every path
# ---------------------------------------------------------------------------

class TestExplicitEvidence:
    """Verify every detected path is explicit and serializable."""

    def test_every_path_has_steps(self, escalation_paths: list):
        for path in escalation_paths:
            assert len(path.steps) >= 1, (
                f"Path {path.path_id} from {path.origin_name} has no steps"
            )

    def test_every_step_has_evidence(self, escalation_paths: list):
        for path in escalation_paths:
            for step in path.steps:
                assert len(step.evidence) >= 1, (
                    f"Step {step.step_number} in path {path.path_id} "
                    f"({step.technique_id}) has no evidence"
                )

    def test_evidence_references_iam_action(self, escalation_paths: list):
        for path in escalation_paths:
            for step in path.steps:
                for ev in step.evidence:
                    assert ":" in ev, (
                        f"Evidence missing concrete IAM action in step "
                        f"{step.step_number} of {path.origin_name}: '{ev}'"
                    )

    def test_every_path_has_valid_severity(self, escalation_paths: list):
        valid_severities = {s.value for s in Severity}
        for path in escalation_paths:
            assert path.severity.value in valid_severities, (
                f"Invalid severity in path {path.path_id}: {path.severity}"
            )

    def test_every_step_has_technique_id(self, escalation_paths: list):
        for path in escalation_paths:
            for step in path.steps:
                assert step.technique_id, (
                    f"Step {step.step_number} in path {path.path_id} "
                    "is missing technique_id"
                )

    def test_every_path_has_origin_and_target(self, escalation_paths: list):
        for path in escalation_paths:
            assert path.origin_arn, f"Path {path.path_id} missing origin_arn"
            assert path.target_arn, f"Path {path.path_id} missing target_arn"

    def test_target_is_admin_node(self, escalation_paths: list):
        for path in escalation_paths:
            assert path.target_arn == "sxaiam::admin", (
                f"Path {path.path_id} does not reach AdminNode: {path.target_arn}"
            )

    def test_path_serializes_to_dict(self, escalation_paths: list):
        for path in escalation_paths:
            result = path.to_dict()
            assert isinstance(result, dict)
            assert "path_id" in result
            assert "severity" in result
            assert "steps" in result
            assert "origin" in result
            assert "target" in result

    def test_path_serializes_to_markdown(self, escalation_paths: list):
        for path in escalation_paths:
            md = path.to_markdown()
            assert isinstance(md, str)
            assert len(md) > 0
            assert path.origin_name in md


# ---------------------------------------------------------------------------
# Tests - output ordering and structure
# ---------------------------------------------------------------------------

class TestOutputStructure:
    """Verify path ordering and internal structure."""

    def test_critical_paths_before_high(self, escalation_paths: list):
        severities = [p.severity.value for p in escalation_paths]
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

        for i in range(len(severities) - 1):
            assert order.get(severities[i], 0) >= order.get(severities[i + 1], 0), (
                f"Incorrect order: {severities[i]} before {severities[i + 1]} "
                f"at position {i}"
            )

    def test_path_ids_are_unique(self, escalation_paths: list):
        ids = [p.path_id for p in escalation_paths]
        assert len(ids) == len(set(ids)), "Duplicate path_ids detected"

    def test_step_numbers_are_sequential(self, escalation_paths: list):
        for path in escalation_paths:
            for i, step in enumerate(path.steps, start=1):
                assert step.step_number == i, (
                    f"Incorrect step_number in path {path.path_id}: "
                    f"expected {i}, found {step.step_number}"
                )
