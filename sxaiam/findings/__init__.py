"""
sxaiam.findings
===============
Escalation techniques and path modeling.

Public interface:
    from sxaiam.findings import EscalationPath
    from sxaiam.findings.technique_base import EscalationTechnique, Severity
"""

from sxaiam.findings.escalation_path import EscalationPath, PathStep
from sxaiam.findings.registry import TechniqueRegistry
from sxaiam.findings.technique_base import EscalationTechnique, Severity, TechniqueMatch

__all__ = [
    "EscalationPath",
    "EscalationTechnique",
    "PathStep",
    "Severity",
    "TechniqueRegistry",
    "TechniqueMatch",
]
