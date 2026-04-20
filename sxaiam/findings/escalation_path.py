"""
sxaiam.findings.escalation_path
================================
EscalationPath — a complete, documented privilege escalation chain.

This is the final output of the analysis engine. Each EscalationPath
represents one way an attacker could move from a starting identity
to a high-privilege target, with full evidence at every step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sxaiam.findings.technique_base import Severity, TechniqueMatch


@dataclass
class PathStep:
    """
    A single step in an escalation path.

    Example:
        PathStep(
            step_number=1,
            from_arn="arn:aws:iam::123:user/developer",
            from_name="developer",
            to_arn="arn:aws:iam::123:role/admin-role",
            to_name="admin-role",
            technique_id="passrole-lambda",
            technique_name="PassRole + Lambda execution",
            evidence=["iam:PassRole on * (via managed_policy: DeveloperPermissions)"],
            api_calls=["lambda:CreateFunction", "lambda:InvokeFunction"],
        )
    """

    step_number: int
    from_arn: str
    from_name: str
    to_arn: str
    to_name: str
    technique_id: str
    technique_name: str
    evidence: list[str] = field(default_factory=list)
    api_calls: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"Step {self.step_number}: {self.from_name} "
            f"→ [{self.technique_name}] → {self.to_name}"
        )


@dataclass
class EscalationPath:
    """
    A complete privilege escalation path from an origin identity
    to a high-privilege target.

    Contains all steps, evidence, and metadata needed to:
    - Understand the attack chain
    - Reproduce it in a pentest
    - Remediate it (which permission to remove)
    - Compare it against Security Hub findings
    """

    path_id: str
    severity: Severity
    origin_arn: str
    origin_name: str
    target_arn: str
    target_name: str
    steps: list[PathStep] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_match(cls, match: TechniqueMatch, path_id: str) -> EscalationPath:
        """
        Build an EscalationPath from a single TechniqueMatch.
        Used for direct single-step escalations.
        """
        step = PathStep(
            step_number=1,
            from_arn=match.origin_arn,
            from_name=match.origin_name,
            to_arn=match.target_arn,
            to_name=match.target_name,
            technique_id=match.technique_id,
            technique_name=match.technique_name,
            evidence=match.evidence,
            api_calls=match.attack_steps,
        )
        return cls(
            path_id=path_id,
            severity=match.severity,
            origin_arn=match.origin_arn,
            origin_name=match.origin_name,
            target_arn=match.target_arn,
            target_name=match.target_name,
            steps=[step],
        )

    @property
    def step_count(self) -> int:
        return len(self.steps)

    @property
    def techniques_used(self) -> list[str]:
        return [s.technique_id for s in self.steps]

    @property
    def all_evidence(self) -> list[str]:
        """Flat list of all evidence across all steps."""
        evidence = []
        for step in self.steps:
            evidence.extend(step.evidence)
        return evidence

    def summary(self) -> str:
        """One-line summary for CLI output and logs."""
        chain = " → ".join(
            [self.origin_name] + [s.to_name for s in self.steps]
        )
        return f"[{self.severity.value}] PATH {self.path_id}: {chain}"

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize to a dict for JSON export.
        This is what the JSON exporter uses in Phase 4.
        """
        return {
            "path_id": self.path_id,
            "severity": self.severity.value,
            "origin": {
                "arn": self.origin_arn,
                "name": self.origin_name,
            },
            "target": {
                "arn": self.target_arn,
                "name": self.target_name,
            },
            "step_count": self.step_count,
            "techniques": self.techniques_used,
            "steps": [
                {
                    "step": s.step_number,
                    "from": s.from_name,
                    "to": s.to_name,
                    "technique": s.technique_name,
                    "evidence": s.evidence,
                    "api_calls": s.api_calls,
                }
                for s in self.steps
            ],
            "all_evidence": self.all_evidence,
        }

    def to_markdown(self) -> str:
        """
        Render as a Markdown block for report output.
        This is what the Markdown exporter uses in Phase 4.
        """
        lines = [
            f"## {self.summary()}",
            "",
            f"**Origin:** `{self.origin_name}` (`{self.origin_arn}`)",
            f"**Target:** `{self.target_name}` (`{self.target_arn}`)",
            f"**Steps:** {self.step_count}",
            "",
            "### Attack chain",
            "",
        ]
        for step in self.steps:
            lines.append(f"**{step.summary()}**")
            for api_call in step.api_calls:
                lines.append(f"- {api_call}")
            lines.append("")
            if step.evidence:
                lines.append("Evidence:")
                for ev in step.evidence:
                    lines.append(f"- `{ev}`")
                lines.append("")

        return "\n".join(lines)
