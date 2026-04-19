"""
Tests for sxaiam.ingestion.client

Uses moto to mock AWS — no real credentials needed.
Validates that IngestionClient correctly collects and parses
the IAM state of a mocked account.
"""

import json
import pytest
import boto3
from moto import mock_aws

from sxaiam.ingestion.client import IngestionClient
from sxaiam.ingestion.models import IAMSnapshot


def make_client() -> IngestionClient:
    """Build an IngestionClient using the current moto session."""
    session = boto3.Session(region_name="us-east-1")
    return IngestionClient(session)


# ---------------------------------------------------------------------------
# Helpers — build mocked IAM resources
# ---------------------------------------------------------------------------

def create_test_user(iam_client: object, name: str = "test-user") -> dict:  # type: ignore[type-arg]
    iam_client.create_user(UserName=name)  # type: ignore[attr-defined]
    return iam_client.get_user(UserName=name)["User"]  # type: ignore[attr-defined]


def create_test_role(iam_client: object, name: str = "test-role") -> dict:  # type: ignore[type-arg]
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }]
    })
    iam_client.create_role(RoleName=name, AssumeRolePolicyDocument=trust)  # type: ignore[attr-defined]
    return iam_client.get_role(RoleName=name)["Role"]  # type: ignore[attr-defined]


def create_test_policy(iam_client: object, name: str = "test-policy") -> dict:  # type: ignore[type-arg]
    doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
    })
    return iam_client.create_policy(  # type: ignore[attr-defined]
        PolicyName=name,
        PolicyDocument=doc,
    )["Policy"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestIngestionClientCollect:

    @mock_aws
    def test_collects_users(self) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        create_test_user(iam, "alice")
        create_test_user(iam, "bob")

        snapshot = make_client().collect()

        user_names = [u.name for u in snapshot.users]
        assert "alice" in user_names
        assert "bob" in user_names

    @mock_aws
    def test_collects_roles(self) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        create_test_role(iam, "my-role")

        snapshot = make_client().collect()

        role_names = [r.name for r in snapshot.roles]
        assert "my-role" in role_names

    @mock_aws
    def test_role_has_trust_policy(self) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        create_test_role(iam, "lambda-role")

        snapshot = make_client().collect()
        role = next(r for r in snapshot.roles if r.name == "lambda-role")

        assert len(role.trust_policy.statements) == 1
        assert role.trust_policy.statements[0].effect == "Allow"

    @mock_aws
    def test_collects_managed_policies(self) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        create_test_policy(iam, "my-policy")

        snapshot = make_client().collect()

        policy_names = [p.name for p in snapshot.policies]
        assert "my-policy" in policy_names

    @mock_aws
    def test_user_with_attached_policy(self) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        create_test_user(iam, "alice")
        policy = create_test_policy(iam, "alice-policy")
        iam.attach_user_policy(
            UserName="alice",
            PolicyArn=policy["Arn"],
        )

        snapshot = make_client().collect()
        alice = next(u for u in snapshot.users if u.name == "alice")

        assert len(alice.attached_policies) == 1
        assert alice.attached_policies[0].name == "alice-policy"

    @mock_aws
    def test_snapshot_has_account_id(self) -> None:
        snapshot = make_client().collect()
        assert snapshot.account_id != ""

    @mock_aws
    def test_build_indexes_work_after_collect(self) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        create_test_user(iam, "alice")

        snapshot = make_client().collect()
        alice_arn = next(u.arn for u in snapshot.users if u.name == "alice")

        assert snapshot.user_by_arn(alice_arn) is not None

    @mock_aws
    def test_empty_account_returns_valid_snapshot(self) -> None:
        snapshot = make_client().collect()
        assert isinstance(snapshot, IAMSnapshot)
        assert snapshot.users == []
        assert snapshot.roles == []
        assert snapshot.scps == []
