"""
sxaiam.ingestion.client
=======================
Connects to AWS and builds a complete IAMSnapshot from a single API call.

The core of this module is get_account_authorization_details — one paginated
call that returns all users, roles, groups and policies in the account.
Everything else is normalization and model construction.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from sxaiam.ingestion.models import (
    AttachedPolicy,
    IAMGroup,
    IAMPolicy,
    IAMRole,
    IAMSnapshot,
    IAMUser,
    PolicyDocument,
)
from sxaiam.ingestion.scps import SCPFetcher

logger = logging.getLogger(__name__)


class IngestionClient:
    """
    Pulls the complete IAM state of an AWS account into an IAMSnapshot.

    Usage:
        client = IngestionClient.from_profile("my-aws-profile")
        snapshot = client.collect()
    """

    def __init__(self, session: boto3.Session) -> None:
        self._session = session
        self._iam = session.client("iam")
        self._sts = session.client("sts")

    @classmethod
    def from_profile(cls, profile: str | None = None) -> IngestionClient:
        """Build a client using a named AWS CLI profile (or the default)."""
        session = boto3.Session(profile_name=profile)
        return cls(session)

    @classmethod
    def from_role_arn(cls, role_arn: str) -> IngestionClient:
        """
        Build a client by assuming a role — useful when sxaiam runs
        inside AWS and needs to scan a different account.
        """
        sts = boto3.client("sts")
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="sxaiam-ingestion",
        )["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        return cls(session)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def collect(self) -> IAMSnapshot:
        """
        Collect the complete IAM state of the account.
        Returns an IAMSnapshot with users, roles, groups, policies and SCPs.
        """
        logger.info("Starting IAM ingestion...")

        account_id = self._get_account_id()
        account_alias = self._get_account_alias()
        logger.info(f"Account: {account_id} ({account_alias or 'no alias'})")

        raw = self._fetch_account_authorization_details()
        logger.info(
            f"Raw data: {len(raw['users'])} users, {len(raw['roles'])} roles, "
            f"{len(raw['groups'])} groups, {len(raw['policies'])} policies"
        )

        users = [self._parse_user(u) for u in raw["users"]]
        roles = [self._parse_role(r) for r in raw["roles"]]
        groups = [self._parse_group(g) for g in raw["groups"]]
        policies = [self._parse_policy(p) for p in raw["policies"]]

        scps = SCPFetcher(self._session).fetch()
        if scps:
            logger.info(f"SCPs found: {len(scps)}")
        else:
            logger.info("No SCPs found (account may not be in an Organization)")

        snapshot = IAMSnapshot(
            account_id=account_id,
            account_alias=account_alias,
            users=users,
            roles=roles,
            groups=groups,
            policies=policies,
            scps=scps,
        )
        snapshot.build_indexes()

        logger.info(f"Ingestion complete: {snapshot.summary()}")
        return snapshot

    # ------------------------------------------------------------------
    # AWS API calls
    # ------------------------------------------------------------------

    def _get_account_id(self) -> str:
        return self._sts.get_caller_identity()["Account"]

    def _get_account_alias(self) -> str:
        try:
            aliases = self._iam.list_account_aliases()["AccountAliases"]
            return aliases[0] if aliases else ""
        except ClientError as e:
            logger.warning(f"Could not fetch account alias: {e}")
            return ""

    def _fetch_account_authorization_details(self) -> dict[str, list[Any]]:
        """
        Single paginated call that returns ALL IAM entities in the account.
        This is the most efficient way to ingest IAM — one call, full picture.
        """
        result: dict[str, list[Any]] = {
            "users": [],
            "roles": [],
            "groups": [],
            "policies": [],
        }

        paginator = self._iam.get_paginator("get_account_authorization_details")
        pages = paginator.paginate(
            Filter=["User", "Role", "Group", "LocalManagedPolicy"]
        )

        for page in pages:
            result["users"].extend(page.get("UserDetailList", []))
            result["roles"].extend(page.get("RoleDetailList", []))
            result["groups"].extend(page.get("GroupDetailList", []))
            result["policies"].extend(page.get("Policies", []))

        return result

    # ------------------------------------------------------------------
    # Parsers — raw AWS dict → typed model
    # ------------------------------------------------------------------

    def _parse_user(self, raw: dict[str, Any]) -> IAMUser:
        """Parse a UserDetail entry from get_account_authorization_details."""
        attached = [
            AttachedPolicy(
                PolicyName=p["PolicyName"],
                PolicyArn=p["PolicyArn"],
            )
            for p in raw.get("AttachedManagedPolicies", [])
        ]

        inline_names = [
            p["PolicyName"]
            for p in raw.get("UserPolicyList", [])
        ]
        inline_docs = {
            p["PolicyName"]: PolicyDocument.from_raw(
                json.loads(p["PolicyDocument"])
                if isinstance(p["PolicyDocument"], str)
                else p["PolicyDocument"]
            )
            for p in raw.get("UserPolicyList", [])
            if "PolicyDocument" in p
        }

        group_names = [
            g["GroupName"] if isinstance(g, dict) else g
            for g in raw.get("GroupList", [])
        ]

        tags = {t["Key"]: t["Value"] for t in raw.get("Tags", [])}

        return IAMUser(
            name=raw["UserName"],
            arn=raw["Arn"],
            user_id=raw["UserId"],
            path=raw.get("Path", "/"),
            tags=tags,
            attached_policies=attached,
            inline_policy_names=inline_names,
            inline_policies=inline_docs,
            group_names=group_names,
        )

    def _parse_role(self, raw: dict[str, Any]) -> IAMRole:
        """Parse a RoleDetail entry from get_account_authorization_details."""
        trust_raw = raw.get("AssumeRolePolicyDocument", {})
        if isinstance(trust_raw, str):
            trust_raw = json.loads(trust_raw)

        attached = [
            AttachedPolicy(
                PolicyName=p["PolicyName"],
                PolicyArn=p["PolicyArn"],
            )
            for p in raw.get("AttachedManagedPolicies", [])
        ]

        inline_names = [
            p["PolicyName"]
            for p in raw.get("RolePolicyList", [])
        ]
        inline_docs = {
            p["PolicyName"]: PolicyDocument.from_raw(
                json.loads(p["PolicyDocument"])
                if isinstance(p["PolicyDocument"], str)
                else p["PolicyDocument"]
            )
            for p in raw.get("RolePolicyList", [])
            if "PolicyDocument" in p
        }

        tags = {t["Key"]: t["Value"] for t in raw.get("Tags", [])}

        return IAMRole(
            name=raw["RoleName"],
            arn=raw["Arn"],
            role_id=raw["RoleId"],
            path=raw.get("Path", "/"),
            description=raw.get("Description", ""),
            tags=tags,
            trust_policy=PolicyDocument.from_raw(trust_raw),
            attached_policies=attached,
            inline_policy_names=inline_names,
            inline_policies=inline_docs,
        )

    def _parse_group(self, raw: dict[str, Any]) -> IAMGroup:
        """Parse a GroupDetail entry from get_account_authorization_details."""
        attached = [
            AttachedPolicy(
                PolicyName=p["PolicyName"],
                PolicyArn=p["PolicyArn"],
            )
            for p in raw.get("AttachedManagedPolicies", [])
        ]

        inline_names = [
            p["PolicyName"]
            for p in raw.get("GroupPolicyList", [])
        ]

        return IAMGroup(
            name=raw["GroupName"],
            arn=raw["Arn"],
            group_id=raw["GroupId"],
            path=raw.get("Path", "/"),
            attached_policies=attached,
            inline_policy_names=inline_names,
        )

    def _parse_policy(self, raw: dict[str, Any]) -> IAMPolicy:
        """Parse a Policy entry from get_account_authorization_details."""
        arn = raw["Arn"]
        document = None

        # The policy document is nested inside PolicyVersionList
        for version in raw.get("PolicyVersionList", []):
            if version.get("IsDefaultVersion"):
                doc_raw = version.get("Document", {})
                if isinstance(doc_raw, str):
                    doc_raw = json.loads(doc_raw)
                document = PolicyDocument.from_raw(doc_raw)
                break

        return IAMPolicy(
            name=raw.get("PolicyName") or raw.get("Name") or raw["Arn"].split("/")[-1],
            arn=arn,
            policy_id=raw.get("PolicyId") or raw.get("Id", ""),
            is_aws_managed=arn.startswith("arn:aws:iam::aws:"),
            document=document,
        )
