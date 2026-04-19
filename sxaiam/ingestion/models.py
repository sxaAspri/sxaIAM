"""
sxaiam.ingestion.models
=======================
Pydantic models representing IAM entities collected from AWS.

These models are the data contract between the ingestion layer and
everything else (policy resolver, graph engine, outputs). If you need
a new field downstream, add it here first.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Policy document primitives
# ---------------------------------------------------------------------------

class PolicyStatement(BaseModel):
    """A single statement inside an IAM policy document."""

    sid: str = Field(default="", alias="Sid")
    effect: str = Field(alias="Effect")                    # "Allow" | "Deny"
    actions: list[str] = Field(default_factory=list)       # normalised to list
    resources: list[str] = Field(default_factory=list)     # normalised to list
    conditions: dict[str, Any] = Field(
        default_factory=dict, alias="Condition"
    )

    model_config = {"populate_by_name": True}

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> PolicyStatement:
        """
        Build from a raw AWS policy statement dict.
        Normalises Action and Resource to always be lists.
        """
        action = raw.get("Action", [])
        resource = raw.get("Resource", [])
        return cls(
            Sid=raw.get("Sid", ""),
            Effect=raw["Effect"],
            actions=action if isinstance(action, list) else [action],
            resources=resource if isinstance(resource, list) else [resource],
            Condition=raw.get("Condition", {}),
        )


class PolicyDocument(BaseModel):
    """A full IAM policy document (the JSON blob)."""

    version: str = Field(default="2012-10-17")
    statements: list[PolicyStatement] = Field(default_factory=list)

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> PolicyDocument:
        """Build from a raw AWS policy document dict."""
        stmts = raw.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        return cls(
            version=raw.get("Version", "2012-10-17"),
            statements=[PolicyStatement.from_raw(s) for s in stmts],
        )


# ---------------------------------------------------------------------------
# Attached policy reference (name + ARN, no document)
# ---------------------------------------------------------------------------

class AttachedPolicy(BaseModel):
    """Reference to a managed policy attached to a user, role, or group."""

    name: str = Field(alias="PolicyName")
    arn: str = Field(alias="PolicyArn")

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Core IAM entities
# ---------------------------------------------------------------------------

class IAMPolicy(BaseModel):
    """
    A managed IAM policy (AWS-managed or customer-managed).
    Includes the full policy document of its default version.
    """

    name: str
    arn: str
    policy_id: str
    is_aws_managed: bool                        # arn starts with arn:aws:iam::aws
    document: PolicyDocument | None = None      # None if document fetch failed


class IAMUser(BaseModel):
    """An IAM user with all their attached and inline policies."""

    name: str
    arn: str
    user_id: str
    path: str = "/"
    tags: dict[str, str] = Field(default_factory=dict)

    # Policies directly on this user
    attached_policies: list[AttachedPolicy] = Field(default_factory=list)
    inline_policy_names: list[str] = Field(default_factory=list)
    inline_policies: dict[str, PolicyDocument] = Field(default_factory=dict)

    # Groups this user belongs to (populated separately)
    group_names: list[str] = Field(default_factory=list)

    @property
    def is_admin(self) -> bool:
        """True if AdministratorAccess is directly attached."""
        admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        return any(p.arn == admin_arn for p in self.attached_policies)


class IAMRole(BaseModel):
    """An IAM role with its trust policy and attached/inline policies."""

    name: str
    arn: str
    role_id: str
    path: str = "/"
    description: str = ""
    tags: dict[str, str] = Field(default_factory=dict)

    # Who can assume this role
    trust_policy: PolicyDocument

    # Permissions this role has
    attached_policies: list[AttachedPolicy] = Field(default_factory=list)
    inline_policy_names: list[str] = Field(default_factory=list)
    inline_policies: dict[str, PolicyDocument] = Field(default_factory=dict)

    @property
    def is_admin(self) -> bool:
        """True if AdministratorAccess is directly attached."""
        admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        return any(p.arn == admin_arn for p in self.attached_policies)

    def can_be_assumed_by_service(self, service: str) -> bool:
        """
        True if the trust policy has a statement allowing
        the given AWS service (e.g. 'lambda.amazonaws.com').
        """
        for stmt in self.trust_policy.statements:
            if stmt.effect != "Allow":
                continue
            if "sts:AssumeRole" not in stmt.actions and "*" not in stmt.actions:
                continue
        return False


class IAMGroup(BaseModel):
    """An IAM group with its attached and inline policies."""

    name: str
    arn: str
    group_id: str
    path: str = "/"

    attached_policies: list[AttachedPolicy] = Field(default_factory=list)
    inline_policy_names: list[str] = Field(default_factory=list)
    inline_policies: dict[str, PolicyDocument] = Field(default_factory=dict)

    # Members (user names)
    member_names: list[str] = Field(default_factory=list)


class SCP(BaseModel):
    """
    A Service Control Policy from AWS Organizations.
    SCPs can restrict what even admin roles can do in member accounts.
    """

    name: str
    arn: str
    policy_id: str
    document: PolicyDocument | None = None


# ---------------------------------------------------------------------------
# The top-level snapshot
# ---------------------------------------------------------------------------

class IAMSnapshot(BaseModel):
    """
    Complete snapshot of an AWS account's IAM state.
    This is what the ingestion layer produces and the rest of sxaiam consumes.
    """

    account_id: str
    account_alias: str = ""

    users: list[IAMUser] = Field(default_factory=list)
    roles: list[IAMRole] = Field(default_factory=list)
    groups: list[IAMGroup] = Field(default_factory=list)
    policies: list[IAMPolicy] = Field(default_factory=list)
    scps: list[SCP] = Field(default_factory=list)       # empty if no Organizations

    # Quick lookup maps (built after ingestion)
    _user_by_arn: dict[str, IAMUser] = {}
    _role_by_arn: dict[str, IAMRole] = {}
    _policy_by_arn: dict[str, IAMPolicy] = {}

    def build_indexes(self) -> None:
        """Build ARN → entity lookup maps for fast access by the graph engine."""
        self._user_by_arn = {u.arn: u for u in self.users}
        self._role_by_arn = {r.arn: r for r in self.roles}
        self._policy_by_arn = {p.arn: p for p in self.policies}

    def user_by_arn(self, arn: str) -> IAMUser | None:
        return self._user_by_arn.get(arn)

    def role_by_arn(self, arn: str) -> IAMRole | None:
        return self._role_by_arn.get(arn)

    def policy_by_arn(self, arn: str) -> IAMPolicy | None:
        return self._policy_by_arn.get(arn)

    def summary(self) -> str:
        return (
            f"IAMSnapshot(account={self.account_id}, "
            f"users={len(self.users)}, roles={len(self.roles)}, "
            f"groups={len(self.groups)}, policies={len(self.policies)}, "
            f"scps={len(self.scps)})"
        )
