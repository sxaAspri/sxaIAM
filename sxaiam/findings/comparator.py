"""
sxaiam/findings/comparator.py

Compara los findings de sxaiam contra los findings de AWS Security Hub
para la misma cuenta, y produce un reporte de la brecha de detección.

Este es el diferenciador clave de sxaiam:
  Security Hub detecta permisos individuales peligrosos.
  sxaiam detecta cadenas de escalación que Security Hub no ve.

Flujo:
  1. Cargar findings de Security Hub (JSON de la API de AWS)
  2. Extraer qué ARNs / acciones menciona Security Hub
  3. Cruzar contra las rutas de sxaiam
  4. Clasificar cada ruta como:
       MISSED    — sxaiam la encontró, Security Hub no la menciona
       PARTIAL   — Security Hub menciona algún permiso de la ruta
       COVERED   — Security Hub menciona explícitamente la identidad y técnica

Output: ComparisonReport con las tres categorías y métricas de cobertura.

Formato de findings de Security Hub esperado:
  El JSON que devuelve aws securityhub get-findings o la consola de AWS.
  Cada finding tiene: Resources[].Id, Title, Description, Severity.Label
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sxaiam.findings.escalation_path import EscalationPath

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Resultado de la comparación por ruta individual
# ---------------------------------------------------------------------------

class CoverageStatus:
    NOT_DETECTED  = "NOT_DETECTED"   # sxaiam la encontró, Security Hub no la menciona
    PARTIAL = "PARTIAL"  # Security Hub menciona algún permiso de la cadena
    COVERED = "COVERED"  # Security Hub cubre explícitamente la identidad


@dataclass
class PathCoverage:
    """
    Resultado de comparar una EscalationPath contra Security Hub.

    Attributes:
        path:            La ruta de sxaiam analizada.
        status:          MISSED, PARTIAL o COVERED.
        matching_findings: Findings de Security Hub que mencionan
                           algún elemento de esta ruta.
        gap_description: Explicación legible de la brecha detectada.
    """
    path:              EscalationPath
    status:            str
    matching_findings: list[dict[str, Any]] = field(default_factory=list)
    gap_description:   str = ""

    @property
    def is_missed(self) -> bool:
        return self.status == CoverageStatus.NOT_DETECTED

    @property
    def is_partial(self) -> bool:
        return self.status == CoverageStatus.PARTIAL

    @property
    def is_covered(self) -> bool:
        return self.status == CoverageStatus.COVERED


# ---------------------------------------------------------------------------
# Reporte completo de comparación
# ---------------------------------------------------------------------------

@dataclass
class ComparisonReport:
    """
    Reporte completo de la comparación sxaiam vs Security Hub.

    Attributes:
        total_sxaiam_paths:     Total de rutas encontradas por sxaiam.
        total_sh_findings:      Total de findings cargados de Security Hub.
        missed:                 Rutas que Security Hub no detectó.
        partial:                Rutas que Security Hub detectó parcialmente.
        covered:                Rutas que Security Hub cubre.
        coverage_percentage:    % de rutas cubiertas por Security Hub.
        gap_percentage:         % de rutas que Security Hub no detectó.
    """
    total_sxaiam_paths: int
    total_sh_findings:  int
    missed:             list[PathCoverage] = field(default_factory=list)
    partial:            list[PathCoverage] = field(default_factory=list)
    covered:            list[PathCoverage] = field(default_factory=list)

    @property
    def coverage_percentage(self) -> float:
        if self.total_sxaiam_paths == 0:
            return 100.0
        covered_count = len(self.covered) + len(self.partial)
        return round(covered_count / self.total_sxaiam_paths * 100, 1)

    @property
    def gap_percentage(self) -> float:
        return round(100.0 - self.coverage_percentage, 1)

    def summary(self) -> str:
        return (
            f"sxaiam found {self.total_sxaiam_paths} escalation path(s). "
            f"Security Hub covers {len(self.covered)} fully, "
            f"{len(self.partial)} partially, "
            f"and {len(self.missed)} with no correlated detection"
            f"({self.gap_percentage}% detection gap)."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "metrics": {
                "total_sxaiam_paths":  self.total_sxaiam_paths,
                "total_sh_findings":   self.total_sh_findings,
                "missed":              len(self.missed),
                "partial":             len(self.partial),
                "covered":             len(self.covered),
                "coverage_percentage": self.coverage_percentage,
                "gap_percentage":      self.gap_percentage,
            },
            "missed_paths": [
                {
                    "path_id":        c.path.path_id,
                    "severity":       c.path.severity.value,
                    "origin":         c.path.origin_name,
                    "target":         c.path.target_name,
                    "techniques":     c.path.techniques_used,
                    "gap_description": c.gap_description,
                }
                for c in self.missed
            ],
            "partial_paths": [
                {
                    "path_id":         c.path.path_id,
                    "severity":        c.path.severity.value,
                    "origin":          c.path.origin_name,
                    "matching_sh_findings": [
                        f.get("Title", "") for f in c.matching_findings
                    ],
                    "gap_description": c.gap_description,
                }
                for c in self.partial
            ],
        }

    def to_markdown(self) -> str:
        lines = [
            "# sxaiam vs AWS Security Hub — Detection Gap Report",
            "",
            "## Summary",
            "",
            f"> {self.summary()}",
            "",
            "## Metrics",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| sxaiam paths found | {self.total_sxaiam_paths} |",
            f"| Security Hub findings loaded | {self.total_sh_findings} |",
            f"| Paths MISSED by Security Hub | {len(self.missed)} |",
            f"| Paths PARTIALLY covered | {len(self.partial)} |",
            f"| Paths COVERED | {len(self.covered)} |",
            f"| Detection gap | **{self.gap_percentage}%** |",
            "",
        ]

        if self.missed:
            lines += [
                "## ❌ Paths with No Correlated Detection",
                "",
                "These escalation chains were found by sxaiam but have",
                "no corresponding finding in Security Hub:",
                "",
            ]
            for coverage in self.missed:
                path = coverage.path
                lines += [
                    f"### 🔴 `{path.origin_name}` → `{path.target_name}`",
                    "",
                    f"- **Severity:** {path.severity.value}",
                    f"- **Techniques:** {', '.join(f'`{t}`' for t in path.techniques_used)}",
                    f"- **Why missed:** {coverage.gap_description}",
                    "",
                ]

        if self.partial:
            lines += [
                "## ⚠️ Paths PARTIALLY covered by Security Hub",
                "",
            ]
            for coverage in self.partial:
                path = coverage.path
                sh_titles = [f.get("Title", "unknown") for f in coverage.matching_findings]
                lines += [
                    f"### 🟠 `{path.origin_name}` → `{path.target_name}`",
                    "",
                    f"- **Severity:** {path.severity.value}",
                    f"- **Related SH findings:** {', '.join(sh_titles)}",
                    f"- **Gap:** {coverage.gap_description}",
                    "",
                ]

        lines += [
            "---",
            "",
            "*Generated by [sxaiam](https://github.com/sxaAspri/sxaIAM)*",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Comparador principal
# ---------------------------------------------------------------------------

class SecurityHubComparator:
    """
    Compara rutas de sxaiam contra findings de AWS Security Hub.

    Uso básico:
        comparator = SecurityHubComparator()
        comparator.load_findings_from_file(Path("sh_findings.json"))
        report = comparator.compare(escalation_paths)
        print(report.to_markdown())

    O cargando findings desde un dict directamente:
        comparator = SecurityHubComparator()
        comparator.load_findings(findings_list)
        report = comparator.compare(paths)
    """

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        # Índices para búsqueda rápida
        self._finding_arns:    set[str] = set()
        self._finding_titles:  set[str] = set()
        self._finding_actions: set[str] = set()

    # ------------------------------------------------------------------
    # Carga de findings
    # ------------------------------------------------------------------

    def load_findings_from_file(self, path: Path) -> None:
        """
        Carga findings de Security Hub desde un archivo JSON.

        El archivo debe ser el output de:
          aws securityhub get-findings --output json > sh_findings.json

        O el export desde la consola de AWS Security Hub.
        """
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)

        # La API devuelve {"Findings": [...]} o directamente [...]
        if isinstance(raw, dict) and "Findings" in raw:
            findings = raw["Findings"]
        elif isinstance(raw, list):
            findings = raw
        else:
            logger.warning("Formato de findings no reconocido: %s", type(raw))
            findings = []

        self.load_findings(findings)

    def load_findings(self, findings: list[dict[str, Any]]) -> None:
        """
        Carga findings de Security Hub desde una lista de dicts.
        Construye índices internos para búsqueda rápida.
        """
        self._findings = findings
        self._build_indexes()
        logger.info("Cargados %d findings de Security Hub", len(findings))

    # ------------------------------------------------------------------
    # Comparación principal
    # ------------------------------------------------------------------

    def compare(self, paths: list[EscalationPath]) -> ComparisonReport:
        """
        Compara las rutas de sxaiam contra los findings cargados.

        Args:
            paths: Lista de EscalationPath del PathFinder.

        Returns:
            ComparisonReport con missed, partial y covered.
        """
        missed:   list[PathCoverage] = []
        partial:  list[PathCoverage] = []
        covered:  list[PathCoverage] = []

        for path in paths:
            coverage = self._classify_path(path)
            if coverage.is_missed:
                missed.append(coverage)
            elif coverage.is_partial:
                partial.append(coverage)
            else:
                covered.append(coverage)

        return ComparisonReport(
            total_sxaiam_paths=len(paths),
            total_sh_findings=len(self._findings),
            missed=missed,
            partial=partial,
            covered=covered,
        )

    # ------------------------------------------------------------------
    # Clasificación de una ruta
    # ------------------------------------------------------------------

    def _classify_path(self, path: EscalationPath) -> PathCoverage:
        """
        Determina si Security Hub cubre esta ruta.

        Lógica de clasificación:
          COVERED:  Security Hub tiene un finding que menciona el ARN
                    de origen Y una acción de la técnica.
          PARTIAL:  Security Hub menciona el ARN de origen O alguna
                    acción de la cadena, pero no ambas.
          MISSED:   Security Hub no menciona nada relacionado con esta ruta.
        """
        # Buscar findings que mencionen el ARN de origen
        origin_findings = self._findings_for_arn(path.origin_arn)

        # Buscar findings que mencionen alguna acción de la cadena
        chain_actions = self._extract_actions_from_path(path)
        action_findings = self._findings_for_actions(chain_actions)

        has_origin_match = len(origin_findings) > 0
        has_action_match = len(action_findings) > 0

        if has_origin_match and has_action_match:
            return PathCoverage(
                path=path,
                status=CoverageStatus.COVERED,
                matching_findings=origin_findings + action_findings,
                gap_description="Security Hub covers this path.",
            )

        if has_origin_match or has_action_match:
            matching = origin_findings or action_findings
            gap = (
                "Security Hub flags the identity but misses the escalation chain."
                if has_origin_match
                else (
                "Security Hub flags a dangerous permission but "
                "doesn't link it to this identity."
                )
            )
            return PathCoverage(
                path=path,
                status=CoverageStatus.PARTIAL,
                matching_findings=matching,
                gap_description=gap,
            )

        # Nada encontrado — MISSED
        techniques_str = ", ".join(path.techniques_used)
        return PathCoverage(
            path=path,
            status=CoverageStatus.NOT_DETECTED,
            matching_findings=[],
            gap_description=(
                f"Security Hub has no finding for `{path.origin_name}` "
                f"using technique(s): {techniques_str}. "
                f"This is a {path.severity.value} escalation path "
                f"that sxaiam detected through permission chaining."
            ),
        )

    # ------------------------------------------------------------------
    # Indexación y búsqueda
    # ------------------------------------------------------------------

    def _build_indexes(self) -> None:
        """Construye índices de ARNs, títulos y acciones para búsqueda O(1)."""
        self._finding_arns    = set()
        self._finding_titles  = set()
        self._finding_actions = set()

        for finding in self._findings:
            # ARNs de recursos afectados
            for resource in finding.get("Resources", []):
                arn = resource.get("Id", "")
                if arn:
                    self._finding_arns.add(arn.lower())

            # Título del finding (contiene nombre del usuario/rol a veces)
            title = finding.get("Title", "")
            if title:
                self._finding_titles.add(title.lower())

            # Acciones IAM mencionadas en el título o descripción
            description = finding.get("Description", "")
            for text in [title, description]:
                for word in text.split():
                    word = word.strip(".,;:`\"'()[]")
                    if ":" in word and word.count(":") == 1:
                        self._finding_actions.add(word.lower())

    def _findings_for_arn(self, arn: str) -> list[dict[str, Any]]:
        """Devuelve findings que mencionan este ARN en sus recursos."""
        arn_lower = arn.lower()
        return [
            f for f in self._findings
            if any(
                r.get("Id", "").lower() == arn_lower
                for r in f.get("Resources", [])
            )
        ]

    def _findings_for_actions(
        self, actions: list[str]
    ) -> list[dict[str, Any]]:
        """Devuelve findings que mencionan alguna de estas acciones IAM."""
        actions_lower = {a.lower() for a in actions}
        result = []
        for finding in self._findings:
            text = (
                finding.get("Title", "") + " " +
                finding.get("Description", "")
            ).lower()
            if any(action in text for action in actions_lower):
                result.append(finding)
        return result

    def _extract_actions_from_path(self, path: EscalationPath) -> list[str]:
        """Extrae todas las acciones IAM mencionadas en la evidencia de la ruta."""
        actions = []
        for step in path.steps:
            for ev in step.evidence:
                # Evidencia formato: "iam:CreatePolicyVersion on * (via ...)"
                parts = ev.split(" ")
                if parts and ":" in parts[0]:
                    actions.append(parts[0])
        return actions
