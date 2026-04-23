"""
sxaiam/output/markdown_exporter.py

Exporta rutas de escalación a un reporte Markdown legible.

El reporte está diseñado para ser entregado directamente a:
  - Pentesters: cadena de ataque paso a paso con comandos
  - Blue Team: qué permiso remover para cortar cada ruta
  - Management: resumen ejecutivo con severidades

Estructura del reporte:
  # sxaiam — IAM Privilege Escalation Report
  ## Executive Summary          (tabla resumen)
  ## Critical Paths             (rutas CRITICAL primero)
  ## High Paths
  ## Medium / Low Paths
  ### PATH-001: alice → AdministratorAccess
      Evidence | Attack chain | Remediation
"""

from __future__ import annotations

import logging
from pathlib import Path

from sxaiam.findings.escalation_path import EscalationPath

logger = logging.getLogger(__name__)

# Emojis de severidad para el reporte
_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "⚪",
}


class MarkdownExporter:
    """
    Genera un reporte Markdown de rutas de escalación.

    Uso básico:
        exporter = MarkdownExporter(account_id="123456789012")
        exporter.export(paths, Path("report.md"))

        # O solo obtener el string:
        md = exporter.to_markdown(paths)
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
    ) -> None:
        """
        Genera el reporte Markdown y lo escribe en output_path.

        Args:
            paths:       Lista de EscalationPath del PathFinder.
            output_path: Ruta del archivo de salida.
        """
        md = self.to_markdown(paths)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md)

        logger.info(
            "Markdown exportado: %s (%d rutas)", output_path, len(paths)
        )

    def to_markdown(self, paths: list[EscalationPath]) -> str:
        """Genera el reporte completo como string Markdown."""
        sections: list[str] = []

        sections.append(self._header())
        sections.append(self._executive_summary(paths))
        sections.append(self._paths_by_severity(paths))
        sections.append(self._footer())

        return "\n\n".join(sections)

    # ------------------------------------------------------------------
    # Secciones del reporte
    # ------------------------------------------------------------------

    def _header(self) -> str:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return (
            f"# sxaiam — IAM Privilege Escalation Report\n\n"
            f"> **Account:** `{self._account_id}`  \n"
            f"> **Generated:** {now}  \n"
            f"> **Tool:** sxaiam v{self._version}  \n"
            f"> **Repo:** github.com/sxaAspri/sxaIAM"
        )

    def _executive_summary(self, paths: list[EscalationPath]) -> str:
        counts: dict[str, int] = {}
        for path in paths:
            key = path.severity.value
            counts[key] = counts.get(key, 0) + 1

        lines = [
            "## Executive Summary",
            "",
            f"**{len(paths)} privilege escalation path(s) found.**",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in counts:
                emoji = _SEVERITY_EMOJI.get(sev, "")
                lines.append(f"| {emoji} {sev} | {counts[sev]} |")

        if not paths:
            lines.append("")
            lines.append("✅ No privilege escalation paths found.")

        return "\n".join(lines)

    def _paths_by_severity(self, paths: list[EscalationPath]) -> str:
        if not paths:
            return ""

        sections: list[str] = ["## Escalation Paths"]

        # Agrupar por severidad
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        grouped: dict[str, list[EscalationPath]] = {}
        for path in paths:
            key = path.severity.value
            grouped.setdefault(key, []).append(path)

        for sev in severity_order:
            if sev not in grouped:
                continue
            emoji = _SEVERITY_EMOJI.get(sev, "")
            sections.append(f"### {emoji} {sev}")
            for i, path in enumerate(grouped[sev], start=1):
                sections.append(self._render_path(path, i))

        return "\n\n".join(sections)

    def _render_path(self, path: EscalationPath, index: int) -> str:
        emoji = _SEVERITY_EMOJI.get(path.severity.value, "")
        lines = [
            f"#### {emoji} `{path.origin_name}` → `{path.target_name}`",
            "",
            f"- **Path ID:** `{path.path_id}`",
            f"- **Origin:** `{path.origin_arn}`",
            f"- **Target:** `{path.target_arn}`",
            f"- **Steps:** {path.step_count}",
            f"- **Techniques:** {', '.join(f'`{t}`' for t in path.techniques_used)}",
            "",
            "**Attack Chain:**",
            "",
        ]

        for step in path.steps:
            lines.append(
                f"**Step {step.step_number}:** "
                f"`{step.from_name}` → [{step.technique_name}] → `{step.to_name}`"
            )
            if step.api_calls:
                lines.append("")
                lines.append("```bash")
                for call in step.api_calls:
                    lines.append(call)
                lines.append("```")
            if step.evidence:
                lines.append("")
                lines.append("*Evidence:*")
                for ev in step.evidence:
                    lines.append(f"- `{ev}`")
            lines.append("")

        lines.append("**Remediation:**")
        lines.append("")
        lines.append(
            "_Remove one of the permissions listed in the evidence above "
            "to break this escalation chain._"
        )

        return "\n".join(lines)

    def _footer(self) -> str:
        return (
            "---\n\n"
            "*Generated by [sxaiam](https://github.com/sxaAspri/sxaIAM) — "
            "AWS IAM Attack Path Analysis*"
        )
