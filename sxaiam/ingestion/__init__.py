"""
sxaiam.ingestion
================
Collects the complete IAM state of an AWS account.

Public interface:
    from sxaiam.ingestion import IngestionClient, IAMSnapshot
"""

from sxaiam.ingestion.client import IngestionClient
from sxaiam.ingestion.models import IAMSnapshot

__all__ = ["IngestionClient", "IAMSnapshot"]
