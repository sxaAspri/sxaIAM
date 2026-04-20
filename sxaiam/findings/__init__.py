"""
sxaiam.findings
===============
Escalation techniques and path modeling.

Public interface:
    from sxaiam.findings import ALL_TECHNIQUES, EscalationPath
    from sxaiam.findings.technique_base import EscalationTechnique, Severity
"""

from sxaiam.findings.escalation_path import EscalationPath, PathStep
from sxaiam.findings.technique_base import EscalationTechnique, Severity, TechniqueMatch
from sxaiam.findings.techniques import ALL_TECHNIQUES

__all__ = [
    "ALL_TECHNIQUES",
    "EscalationPath",
    "EscalationTechnique",
    "PathStep",
    "Severity",
    "TechniqueMatch",
]
