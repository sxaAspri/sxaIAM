"""
Tests for sxaiam.ingestion.models

These tests verify that the Pydantic models correctly parse
raw AWS API responses into typed, structured data.
No AWS credentials needed — pure unit tests.
"""

import pytest
from sxaiam.ingestion.models import (
    AttachedPolicy,
    IAMPolicy,
    IAMRole,
    IAMSnapshot,
    IAMUser,
    PolicyDocument,
    PolicyStatement,
)


class TestPolicyStatement:
    def test_parses_single_action_as_list(self) -> None:
        raw = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        stmt = PolicyStatement.from_raw(raw)
        assert stmt.actions == ["s3:GetObject"]
        assert stmt.resources == ["*"]

    def test_parses_list_action(self) -> None:
        raw = {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "*",
        }
        stmt = PolicyStatement.from_raw(raw)
        assert len(stmt.actions) == 2

    def test_effect_is_preserved(self) -> None:
        raw = {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}
        stmt = PolicyStatement.from_raw(raw)
        assert stmt.effect == "Deny"

    def test_sid_defaults_to_empty_string(self) -> None:
        raw = {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        stmt = PolicyStatement.from_raw(raw)
        assert stmt.sid == ""

    def test_condition_defaults_to_empty_dict(self) -> None:
        raw = {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        stmt = PolicyStatement.from_raw(raw)
        assert stmt.conditions == {}


class TestPolicyDocument:
    def test_parses_single_statement(self) -> None:
        raw = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        }
        doc = PolicyDocument.from_raw(raw)
        assert len(doc.statements) == 1

    def test_parses_list_of_statements(self) -> None:
        raw = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
            ],
        }
        doc = PolicyDocument.from_raw(raw)
        assert len(doc.statements) == 2

    def test_version_defaults_correctly(self) -> None:
        raw = {"Statement": []}
        doc = PolicyDocument.from_raw(raw)
        assert doc.version == "2012-10-17"


class TestIAMUser:
    def _make_user(self, **kwargs: object) -> IAMUser:
        defaults = dict(
            name="test-user",
            arn="arn:aws:iam::123456789012:user/test-user",
            user_id="AIDATEST123",
        )
        defaults.update(kwargs)
        return IAMUser(**defaults)  # type: ignore[arg-type]

    def test_is_admin_false_by_default(self) -> None:
        user = self._make_user()
        assert user.is_admin is False

    def test_is_admin_true_when_admin_policy_attached(self) -> None:
        user = self._make_user(
            attached_policies=[
                AttachedPolicy(
                    PolicyName="AdministratorAccess",
                    PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
                )
            ]
        )
        assert user.is_admin is True

    def test_group_names_defaults_to_empty(self) -> None:
        user = self._make_user()
        assert user.group_names == []


class TestIAMSnapshot:
    def test_summary_contains_counts(self) -> None:
        snapshot = IAMSnapshot(account_id="123456789012")
        assert "users=0" in snapshot.summary()
        assert "roles=0" in snapshot.summary()

    def test_build_indexes_enables_arn_lookup(self) -> None:
        user = IAMUser(
            name="u",
            arn="arn:aws:iam::123:user/u",
            user_id="UID1",
        )
        snapshot = IAMSnapshot(account_id="123", users=[user])
        snapshot.build_indexes()
        assert snapshot.user_by_arn("arn:aws:iam::123:user/u") is user

    def test_lookup_returns_none_for_missing_arn(self) -> None:
        snapshot = IAMSnapshot(account_id="123")
        snapshot.build_indexes()
        assert snapshot.user_by_arn("arn:aws:iam::123:user/nobody") is None
