"""
sxaiam.findings.technique_base
===============================
Abstract base class for all IAM privilege escalation techniques.

Every technique must answer two questions:
  1. Does this identity have the permissions needed to execute this technique?
  2. If yes, what edges does it create in the attack graph?

Adding a new technique = creating a new class that inherits from
EscalationTechnique. The graph engine never needs to change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sxaiam.ingestion.models import IAMSnapshot
    from sxaiam.resolver.models import ResolvedIdentity


class Severity(str, Enum):
    CRITICAL = "CRITICAL"   # admin in 1-2 steps, no external dependency
    HIGH     = "HIGH"       # admin in 2-3 steps, may need another service
    MEDIUM   = "MEDIUM"     # admin possible but requires specific conditions
    LOW      = "LOW"        # limited impact or hard to exploit
    INFO     = "INFO"       # trust policy edge — not directly exploitable


@dataclass
class TechniqueMatch:
    """
    Result of a technique check against a single identity.
    Produced when a technique finds the required permissions.

    This is the raw match — EscalationPath wraps it with full context.
    """

    technique_id: str
    technique_name: str
    severity: Severity

    # The identity that has the escalation capability
    origin_arn: str
    origin_name: str

    # The target they can escalate to (a role ARN, user ARN, or policy ARN)
    target_arn: str
    target_name: str

    # Human-readable description of the attack chain
    description: str

    # Explicit evidence: which permissions justify this match
    evidence: list[str] = field(default_factory=list)

    # Step-by-step API calls an attacker would make
    attack_steps: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"[{self.severity.value}] {self.technique_name}: "
            f"{self.origin_name} → {self.target_name}"
        )


class EscalationTechnique(ABC):
    """
    Abstract base class for privilege escalation techniques.

    Subclasses implement check() to detect whether a given identity
    has the permissions needed to execute this technique.

    The technique is stateless — it receives the identity and snapshot
    at check time, never stores them.
    """

    @property
    @abstractmethod
    def technique_id(self) -> str:
        """Unique identifier, e.g. 'create-policy-version'"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name, e.g. 'CreatePolicyVersion swap'"""

    @property
    @abstractmethod
    def severity(self) -> Severity:
        """Default severity of this technique."""

    @property
    @abstractmethod
    def required_actions(self) -> list[str]:
        """
        IAM actions required to execute this technique.
        Used for documentation and coverage reporting.
        """

    @property
    @abstractmethod
    def description(self) -> str:
        """One-paragraph explanation of the technique."""

    @abstractmethod
    def check(
        self,
        identity: ResolvedIdentity,
        snapshot: IAMSnapshot,
    ) -> list[TechniqueMatch]:
        """
        Check if the given identity can execute this technique.

        Returns a list of TechniqueMatch objects — one per viable
        escalation target found. Returns [] if the technique does
        not apply to this identity.

        Implementations should:
        - Check identity.can(action, resource) for required permissions
        - Look up viable targets in the snapshot
        - Build TechniqueMatch with explicit evidence from the identity
        """

    def _build_evidence(
        self,
        identity: ResolvedIdentity,
        actions: list[str],
    ) -> list[str]:
        """
        Helper: collect evidence strings for a list of actions.
        Returns one evidence string per matching permission found.
        """
        evidence = []
        for action in actions:
            for perm in identity.permissions_for_action(action):
                evidence.append(perm.as_evidence())
        return evidence
