"""
sxaiam/output/json_exporter.py

Exporta rutas de escalación a JSON estructurado.

El JSON producido es la fuente de verdad para integraciones externas:
  - SIEM / Splunk ingestion
  - Scripts de remediación automatizada
  - Comparador vs Security Hub (Fase 4C)
  - APIs que consuman los findings de sxaiam

Estructura del JSON de salida:
{
  "metadata": {
    "generated_at": "2026-04-22T...",
    "sxaiam_version": "0.1.0",
    "account_id": "123456789012",
    "total_paths": 5,
    "critical": 2,
    "high": 3
  },
  "paths": [
    {
      "path_id": "uuid",
      "severity": "CRITICAL",
      "origin": { "arn": "...", "name": "..." },
      "target": { "arn": "...", "name": "..." },
      "step_count": 2,
      "techniques": ["create-policy-version"],
      "steps": [...],
      "all_evidence": [...]
    }
  ]
}
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sxaiam.findings.escalation_path import EscalationPath

logger = logging.getLogger(__name__)


class JSONExporter:
    """
    Serializa una lista de EscalationPath a JSON.

    Uso básico:
        exporter = JSONExporter(account_id="123456789012")
        exporter.export(paths, Path("report.json"))

        # O solo obtener el dict sin escribir archivo:
        data = exporter.to_dict(paths)
    """

    def __init__(
        self,
        account_id: str = "unknown",
        version: str = "0.1.0",
    ) -> None:
        self._account_id = account_id
        self._version    = version

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def export(
        self,
        paths: list[EscalationPath],
        output_path: Path,
        indent: int = 2,
    ) -> None:
        """
        Serializa las rutas y escribe el JSON en output_path.

        Args:
            paths:       Lista de EscalationPath del PathFinder.
            output_path: Ruta del archivo de salida (se crea si no existe).
            indent:      Indentación del JSON (default 2).
        """
        data = self.to_dict(paths)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)

        logger.info(
            "JSON exportado: %s (%d rutas)", output_path, len(paths)
        )

    def to_dict(self, paths: list[EscalationPath]) -> dict[str, Any]:
        """
        Convierte las rutas a un dict serializable.
        Útil para testing o para combinar con otros outputs.
        """
        severity_counts = _count_by_severity(paths)

        return {
            "metadata": {
                "generated_at":   _now_iso(),
                "sxaiam_version": self._version,
                "account_id":     self._account_id,
                "total_paths":    len(paths),
                "critical":       severity_counts.get("CRITICAL", 0),
                "high":           severity_counts.get("HIGH", 0),
                "medium":         severity_counts.get("MEDIUM", 0),
                "low":            severity_counts.get("LOW", 0),
            },
            "paths": [self._serialize_path(p) for p in paths],
        }

    def to_json(self, paths: list[EscalationPath], indent: int = 2) -> str:
        """Devuelve el JSON como string — útil para CLI stdout."""
        return json.dumps(self.to_dict(paths), indent=indent, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Serialización interna
    # ------------------------------------------------------------------

    def _serialize_path(self, path: EscalationPath) -> dict[str, Any]:
        """Convierte un EscalationPath al formato JSON de salida."""
        return {
            "path_id":    path.path_id,
            "severity":   path.severity.value,
            "origin": {
                "arn":  path.origin_arn,
                "name": path.origin_name,
            },
            "target": {
                "arn":  path.target_arn,
                "name": path.target_name,
            },
            "step_count":   path.step_count,
            "techniques":   path.techniques_used,
            "steps": [
                {
                    "step":       s.step_number,
                    "from_arn":   s.from_arn,
                    "from_name":  s.from_name,
                    "to_arn":     s.to_arn,
                    "to_name":    s.to_name,
                    "technique":  s.technique_name,
                    "severity":   s.severity,
                    "evidence":   s.evidence,
                    "api_calls":  s.api_calls,
                }
                for s in path.steps
            ],
            "all_evidence": path.all_evidence,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _count_by_severity(paths: list[EscalationPath]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in paths:
        key = path.severity.value
        counts[key] = counts.get(key, 0) + 1
    return counts
