"""
sxaiam.findings.techniques
===========================
The 5 IAM privilege escalation techniques modeled in sxaiam.

Each technique is a self-contained class that knows:
  - What permissions it needs
  - How to find viable targets in the snapshot
  - What evidence to attach to each match

Reference: Rhino Security Labs — AWS IAM Privilege Escalation Methods
https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sxaiam.findings.technique_base import (
    EscalationTechnique,
    Severity,
    TechniqueMatch,
)

if TYPE_CHECKING:
    from sxaiam.ingestion.models import IAMSnapshot
    from sxaiam.resolver.models import ResolvedIdentity


# ---------------------------------------------------------------------------
# Technique 1 — CreatePolicyVersion swap
# ---------------------------------------------------------------------------

class CreatePolicyVersionTechnique(EscalationTechnique):
    """
    The attacker has iam:CreatePolicyVersion on a managed policy.
    They create a new version with Allow *:* and set it as default.
    If that policy is attached to their own identity, they become admin.

    Permissions needed:
      - iam:CreatePolicyVersion (on the target policy)
      - iam:SetDefaultPolicyVersion (on the target policy) [optional but common]
    """

    @property
    def technique_id(self) -> str:
        return "create-policy-version"

    @property
    def name(self) -> str:
        return "CreatePolicyVersion swap"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def required_actions(self) -> list[str]:
        return ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]

    @property
    def description(self) -> str:
        return (
            "The identity has iam:CreatePolicyVersion on a managed policy "
            "that is also attached to itself. By creating a new policy version "
            "with Allow *:* and setting it as default, the identity grants "
            "itself full administrator access."
        )

    def check(
        self,
        identity: ResolvedIdentity,
        snapshot: IAMSnapshot,
        ) -> list[TechniqueMatch]:
        matches = []

        # Primero verificar que la identidad puede CreatePolicyVersion
        can_create_any = identity.can("iam:CreatePolicyVersion", "*")

        if not can_create_any:
            has_specific = any(
                identity.can("iam:CreatePolicyVersion", p.arn)
                for p in snapshot.policies
                if not p.is_aws_managed
            )
            if not has_specific:
                return []

        # Solo buscar en políticas adjuntas directamente a esta identidad
        attached_arns: set[str] = set()

        for user in snapshot.users:
            if user.arn == identity.arn:
                attached_arns = {p.arn for p in user.attached_policies}
                break

        for role in snapshot.roles:
            if role.arn == identity.arn:
                attached_arns = {p.arn for p in role.attached_policies}
                break

        for policy in snapshot.policies:
            if policy.is_aws_managed:
                continue

            if policy.arn not in attached_arns:
                continue

            can_create = (
                identity.can("iam:CreatePolicyVersion", policy.arn)
                or identity.can("iam:CreatePolicyVersion", "*")
            )
            if not can_create:
                continue

            evidence = self._build_evidence(
                identity,
                ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
            )

            matches.append(TechniqueMatch(
                technique_id=self.technique_id,
                technique_name=self.name,
                severity=self.severity,
                origin_arn=identity.arn,
                origin_name=identity.name,
                target_arn=policy.arn,
                target_name=policy.name,
                description=self.description,
                evidence=evidence,
                attack_steps=[
                    f"1. Call iam:CreatePolicyVersion on {policy.arn} "
                    f'with document {{"Effect":"Allow","Action":"*","Resource":"*"}}',
                    "2. Call iam:SetDefaultPolicyVersion to activate the new version",
                    f"3. {identity.name} now has AdministratorAccess via {policy.name}",
                ],
            ))

        return matches

    def _policy_attached_to_identity(
        self, policy_arn: str, identity_arn: str, snapshot: IAMSnapshot
    ) -> bool:
        """Check if a policy is attached to the given identity."""
        for user in snapshot.users:
            if user.arn == identity_arn:
                return any(p.arn == policy_arn for p in user.attached_policies)
        for role in snapshot.roles:
            if role.arn == identity_arn:
                return any(p.arn == policy_arn for p in role.attached_policies)
        return False


# ---------------------------------------------------------------------------
# Technique 2 — PassRole + Lambda
# ---------------------------------------------------------------------------

class PassRoleLambdaTechnique(EscalationTechnique):
    """
    The attacker has iam:PassRole on a privileged role AND
    lambda:CreateFunction + lambda:InvokeFunction.
    They create a Lambda function that runs AS the privileged role,
    then invoke it to execute arbitrary code with those permissions.

    Permissions needed:
      - iam:PassRole (on a role with high privileges)
      - lambda:CreateFunction
      - lambda:InvokeFunction
    """

    @property
    def technique_id(self) -> str:
        return "passrole-lambda"

    @property
    def name(self) -> str:
        return "PassRole + Lambda execution"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def required_actions(self) -> list[str]:
        return ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]

    @property
    def description(self) -> str:
        return (
            "The identity has iam:PassRole on a privileged role and can create "
            "Lambda functions. By creating a Lambda function that assumes the "
            "privileged role, then invoking it, the attacker can execute "
            "arbitrary code with the permissions of that role."
        )

    def check(
        self,
        identity: ResolvedIdentity,
        snapshot: IAMSnapshot,
    ) -> list[TechniqueMatch]:
        # Must be able to create and invoke Lambda functions
        can_create = identity.can("lambda:CreateFunction")
        can_invoke = identity.can("lambda:InvokeFunction")
        if not (can_create and can_invoke):
            return []

        matches = []

        # Find roles this identity can pass to Lambda
        for role in snapshot.roles:
            # Can pass this specific role?
            can_pass = (
                identity.can("iam:PassRole", role.arn)
                or identity.can("iam:PassRole", "*")
            )
            if not can_pass:
                continue

            # The role must be assumable by Lambda
            if not self._lambda_can_assume(role):
                continue

            # Target role should have meaningful permissions
            if not role.is_admin and not role.attached_policies:
                continue

            evidence = self._build_evidence(
                identity,
                ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
            )

            matches.append(TechniqueMatch(
                technique_id=self.technique_id,
                technique_name=self.name,
                severity=self.severity,
                origin_arn=identity.arn,
                origin_name=identity.name,
                target_arn="sxaiam::admin",
                target_name=role.name,
                description=self.description,
                evidence=evidence,
                attack_steps=[
                    f"1. Call lambda:CreateFunction with Role={role.arn}",
                    f"2. Function runtime: call sts:GetCallerIdentity to confirm role",
                    f"3. Call lambda:InvokeFunction to execute arbitrary code as {role.name}",
                    f"4. {role.name} has {len(role.attached_policies)} attached policies",
                ],
            ))

        return matches

    def _lambda_can_assume(self, role) -> bool:
        """True si el trust policy del rol permite lambda.amazonaws.com."""
        for stmt in role.trust_policy.statements:
            if stmt.effect != "Allow":
                continue
            principal = stmt.principal
            if not isinstance(principal, dict):
                continue
            service = principal.get("Service", "")
            if isinstance(service, str):
                service = [service]
            if any("lambda.amazonaws.com" in s for s in service):
                    return True
        return False


# ---------------------------------------------------------------------------
# Technique 3 — AssumeRole chaining
# ---------------------------------------------------------------------------

class AssumeRoleChainTechnique(EscalationTechnique):
    """
    The attacker controls a role that has sts:AssumeRole on a more
    privileged role, AND the target role's trust policy allows it.
    They assume the privileged role directly.

    Permissions needed:
      - sts:AssumeRole (on the target role)
      - Target role's trust policy must allow the source identity
    """

    @property
    def technique_id(self) -> str:
        return "assumerole-chain"

    @property
    def name(self) -> str:
        return "AssumeRole chaining"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def required_actions(self) -> list[str]:
        return ["sts:AssumeRole"]

    @property
    def description(self) -> str:
        return (
            "The identity has sts:AssumeRole on a privileged role, and that "
            "role's trust policy allows this identity to assume it. The attacker "
            "can directly pivot to the privileged role with a single API call."
        )
    
    def _identity_allowed_by_trust_policy(self, identity_arn: str, role) -> bool:
        """True si la trust policy del rol permite que esta identidad lo asuma."""
        for stmt in role.trust_policy.statements:
            if stmt.effect != "Allow":
                continue
            principal = stmt.principal
            if not isinstance(principal, dict):
                continue
            aws = principal.get("AWS", "")
            if isinstance(aws, str):
                aws = [aws]
            for p in aws:
                if p == identity_arn or p.endswith(":root"):
                    return True
        return False

    def check(
        self,
        identity: ResolvedIdentity,
        snapshot: IAMSnapshot,
    ) -> list[TechniqueMatch]:
        matches = []

        for role in snapshot.roles:
            if role.arn == identity.arn:
                continue  # skip self

            # Identity must have sts:AssumeRole on this role
            can_assume = (
                identity.can("sts:AssumeRole", role.arn)
                or identity.can("sts:AssumeRole", "*")
            )
            if not can_assume:
                continue

            if not self._identity_allowed_by_trust_policy(identity.arn, role):
                continue

            # Role must have meaningful permissions to be worth chaining to
            if not role.attached_policies and not role.inline_policies:
                continue

            evidence = self._build_evidence(identity, ["sts:AssumeRole"])

            matches.append(TechniqueMatch(
                technique_id=self.technique_id,
                technique_name=self.name,
                severity=self.severity,
                origin_arn=identity.arn,
                origin_name=identity.name,
                target_arn="sxaiam::admin",
                target_name=role.name,
                description=self.description,
                evidence=evidence,
                attack_steps=[
                    f"1. Call sts:AssumeRole with RoleArn={role.arn}",
                    f"2. Receive temporary credentials for {role.name}",
                    f"3. Use credentials — {role.name} has "
                    f"{len(role.attached_policies)} attached policies",
                ],
            ))

        return matches
    

    def _identity_allowed_by_trust_policy(self, identity_arn: str, role) -> bool:
        """True si la trust policy del rol permite que esta identidad lo asuma."""
        for stmt in role.trust_policy.statements:
            if stmt.effect != "Allow":
                continue
            principal = stmt.principal
            if not isinstance(principal, dict):
                continue
            aws = principal.get("AWS", "")
            if isinstance(aws, str):
                aws = [aws]
            for p in aws:
                if p == identity_arn or p.endswith(":root"):
                    return True
        return False


# ---------------------------------------------------------------------------
# Technique 4 — AttachUserPolicy / AttachRolePolicy
# ---------------------------------------------------------------------------

class AttachPolicyTechnique(EscalationTechnique):
    """
    The attacker has iam:AttachUserPolicy or iam:AttachRolePolicy
    with a broad resource scope. They attach AdministratorAccess
    directly to themselves or to a role they control.

    Permissions needed:
      - iam:AttachUserPolicy (on self or *) OR
      - iam:AttachRolePolicy (on a role they control)
    """

    @property
    def technique_id(self) -> str:
        return "attach-policy"

    @property
    def name(self) -> str:
        return "AttachUserPolicy / AttachRolePolicy self-escalation"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def required_actions(self) -> list[str]:
        return ["iam:AttachUserPolicy", "iam:AttachRolePolicy"]

    @property
    def description(self) -> str:
        return (
            "The identity has iam:AttachUserPolicy or iam:AttachRolePolicy "
            "with a resource scope that includes itself. It can attach "
            "AdministratorAccess directly, becoming an admin in one API call."
        )

    def check(
        self,
        identity: ResolvedIdentity,
        snapshot: IAMSnapshot,
    ) -> list[TechniqueMatch]:
        matches = []
        admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"

        # Check iam:AttachUserPolicy on self or *
        can_attach_user = (
            identity.can("iam:AttachUserPolicy", identity.arn)
            or identity.can("iam:AttachUserPolicy", "*")
        )

        if can_attach_user:
            evidence = self._build_evidence(identity, ["iam:AttachUserPolicy"])
            matches.append(TechniqueMatch(
                technique_id=self.technique_id,
                technique_name=self.name,
                severity=self.severity,
                origin_arn=identity.arn,
                origin_name=identity.name,
                target_arn=admin_policy_arn,
                target_name="AdministratorAccess",
                description=self.description,
                evidence=evidence,
                attack_steps=[
                    f"1. Call iam:AttachUserPolicy with "
                    f"UserName={identity.name} and "
                    f"PolicyArn={admin_policy_arn}",
                    f"2. {identity.name} now has AdministratorAccess",
                ],
            ))

        # Check iam:AttachRolePolicy on any role
        can_attach_role = (
            identity.can("iam:AttachRolePolicy", "*")
        )
        if can_attach_role:
            evidence = self._build_evidence(identity, ["iam:AttachRolePolicy"])
            matches.append(TechniqueMatch(
                technique_id=self.technique_id,
                technique_name=self.name,
                severity=self.severity,
                origin_arn=identity.arn,
                origin_name=identity.name,
                target_arn=admin_policy_arn,
                target_name="AdministratorAccess (via role)",
                description=self.description,
                evidence=evidence,
                attack_steps=[
                    "1. Call iam:AttachRolePolicy on any role with "
                    f"PolicyArn={admin_policy_arn}",
                    "2. Assume that role to gain AdministratorAccess",
                ],
            ))

        return matches


# ---------------------------------------------------------------------------
# Technique 5 — CreateAccessKey (credential takeover)
# ---------------------------------------------------------------------------

class CreateAccessKeyTechnique(EscalationTechnique):
    """
    The attacker has iam:CreateAccessKey on a more privileged user.
    They generate a new access key for that user and authenticate as them.

    Permissions needed:
      - iam:CreateAccessKey (on a target user with higher privileges)
    """

    @property
    def technique_id(self) -> str:
        return "create-access-key"

    @property
    def name(self) -> str:
        return "CreateAccessKey credential takeover"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def required_actions(self) -> list[str]:
        return ["iam:CreateAccessKey"]

    @property
    def description(self) -> str:
        return (
            "The identity has iam:CreateAccessKey on a more privileged user. "
            "By generating a new access key for that user, the attacker can "
            "authenticate as them and inherit all their permissions."
        )

    def check(
        self,
        identity: ResolvedIdentity,
        snapshot: IAMSnapshot,
    ) -> list[TechniqueMatch]:
        matches = []

        for target_user in snapshot.users:
            if target_user.arn == identity.arn:
                continue  # skip self

            # Can create access key for this specific user?
            can_create = (
                identity.can("iam:CreateAccessKey", target_user.arn)
                or identity.can("iam:CreateAccessKey", "*")
            )
            if not can_create:
                continue

            # Target must have meaningful permissions
            if not target_user.attached_policies and not target_user.inline_policies:
                continue

            evidence = self._build_evidence(identity, ["iam:CreateAccessKey"])

            matches.append(TechniqueMatch(
                technique_id=self.technique_id,
                technique_name=self.name,
                severity=self.severity,
                origin_arn=identity.arn,
                origin_name=identity.name,
                target_arn="sxaiam::admin",
                target_name=target_user.name,
                description=self.description,
                evidence=evidence,
                attack_steps=[
                    f"1. Call iam:CreateAccessKey with UserName={target_user.name}",
                    f"2. Store the returned AccessKeyId and SecretAccessKey",
                    f"3. Configure AWS CLI with the new credentials",
                    f"4. Operate as {target_user.name} with their full permissions",
                ],
            ))

        return matches


# ---------------------------------------------------------------------------
# Registry — all techniques available in sxaiam
# ---------------------------------------------------------------------------

ALL_TECHNIQUES = [
    CreatePolicyVersionTechnique,
    PassRoleLambdaTechnique,
    AssumeRoleChainTechnique,
    AttachPolicyTechnique,
    CreateAccessKeyTechnique,
]
