"""
sxaiam.resolver
===============
Computes effective IAM permissions from a snapshot.

Public interface:
    from sxaiam.resolver import PolicyResolver
"""

from sxaiam.resolver.engine import PolicyResolver
from sxaiam.resolver.models import EffectivePermission, ResolvedIdentity

__all__ = ["PolicyResolver", "EffectivePermission", "ResolvedIdentity"]
