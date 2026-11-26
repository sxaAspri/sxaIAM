"""
sxaiam.providers.gcp.loader
===========================
Carga un snapshot GCP desde JSON y lo convierte en ``GCPSnapshot``.

Formato de entrada (envoltorio sobre la salida cruda de gcloud)::

    {
      "project_id": "...",
      "project_iam_policy": <gcloud projects get-iam-policy <id> --format=json>,
      "service_accounts": [
        {"email": "...",
         "iam_policy": <gcloud iam service-accounts get-iam-policy <email> --format=json>}
      ]
    }

Particularidades de gcloud que se absorben aquí:
- Una policy sin bindings no trae la clave ``bindings`` (p. ej. ``{"etag": "ACAB"}``).
- ``etag`` y ``version`` se ignoran.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sxaiam.providers.gcp.models import GCPBinding, GCPServiceAccount, GCPSnapshot


class GCPSnapshotError(ValueError):
    """El JSON no tiene el formato de snapshot GCP esperado."""


def load_snapshot(path: str | Path) -> GCPSnapshot:
    """Lee un archivo JSON de snapshot GCP."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GCPSnapshotError(f"{path}: JSON inválido: {exc}") from exc
    return parse_snapshot(raw)


def parse_snapshot(raw: Any) -> GCPSnapshot:
    """Convierte el dict del envoltorio en ``GCPSnapshot``."""
    if not isinstance(raw, dict):
        raise GCPSnapshotError("el snapshot debe ser un objeto JSON")
    if not raw.get("project_id"):
        raise GCPSnapshotError("falta 'project_id'")

    try:
        project_bindings = _parse_policy(raw.get("project_iam_policy") or {})
        service_accounts = [
            _parse_service_account(sa) for sa in raw.get("service_accounts") or []
        ]
        snapshot = GCPSnapshot(
            project_id=raw["project_id"],
            project_bindings=project_bindings,
            service_accounts=service_accounts,
        )
    except ValidationError as exc:
        raise GCPSnapshotError(f"snapshot GCP inválido: {exc}") from exc

    _check_unique_emails(snapshot)
    return snapshot


def _parse_policy(policy: Any) -> list[GCPBinding]:
    if not isinstance(policy, dict):
        raise GCPSnapshotError(
            f"la IAM policy debe ser un objeto JSON, no {type(policy).__name__}"
        )
    return [GCPBinding.model_validate(b) for b in policy.get("bindings") or []]


def _parse_service_account(raw: Any) -> GCPServiceAccount:
    if not isinstance(raw, dict):
        raise GCPSnapshotError(
            f"cada service account debe ser un objeto JSON, no {type(raw).__name__}"
        )
    if not raw.get("email"):
        raise GCPSnapshotError("service account sin 'email'")
    return GCPServiceAccount(
        email=raw["email"],
        bindings=_parse_policy(raw.get("iam_policy") or {}),
    )


def _check_unique_emails(snapshot: GCPSnapshot) -> None:
    seen: set[str] = set()
    for sa in snapshot.service_accounts:
        if sa.email in seen:
            raise GCPSnapshotError(f"service account duplicada: {sa.email}")
        seen.add(sa.email)
