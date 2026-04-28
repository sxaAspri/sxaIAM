"""
sxaiam.ingestion.scps
=====================
Fetches Service Control Policies from AWS Organizations.

SCPs are account-level restrictions that override even admin permissions.
This module is intentionally isolated — if the account has no Organizations,
it returns an empty list without failing the rest of the ingestion.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from sxaiam.ingestion.models import SCP, PolicyDocument

logger = logging.getLogger(__name__)


class SCPFetcher:
    """
    Downloads all SCPs attached to the current account via AWS Organizations.

    If the account is not part of an Organization, or the caller does not
    have organizations:ListPolicies permission, returns an empty list
    instead of raising — ingestion continues without SCP context.
    """

    def __init__(self, session: boto3.Session) -> None:
        self._org = session.client("organizations")

    def fetch(self) -> list[SCP]:
        """
        Return all SCPs in the Organization.
        Returns [] if Organizations is not available or not accessible.
        """
        try:
            return self._fetch_all_scps()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in (
                "AWSOrganizationsNotInUseException",
                "AccessDeniedException",
            ):
                logger.info(f"SCPs not available: {code} — continuing without them")
                return []
            raise

    def _fetch_all_scps(self) -> list[SCP]:
        paginator = self._org.get_paginator("list_policies")
        raw_policies: list[dict[str, Any]] = []

        for page in paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
            raw_policies.extend(page.get("Policies", []))

        scps = []
        for raw in raw_policies:
            scp = self._fetch_scp_with_document(raw)
            if scp:
                scps.append(scp)

        return scps

    def _fetch_scp_with_document(self, raw: dict[str, Any]) -> SCP | None:
        """Fetch the policy document for a single SCP."""
        try:
            response = self._org.describe_policy(PolicyId=raw["Id"])
            policy = response["Policy"]
            doc_raw = json.loads(policy["Content"])
            document = PolicyDocument.from_raw(doc_raw)
        except (ClientError, KeyError, json.JSONDecodeError) as e:
            logger.warning(f"Could not fetch SCP document for {raw.get('Id')}: {e}")
            document = None

        return SCP(
            name=raw["Name"],
            arn=raw["Arn"],
            policy_id=raw["Id"],
            document=document,
        )
