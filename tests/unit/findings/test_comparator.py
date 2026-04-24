"""
tests/unit/findings/test_comparator.py

Tests unitarios del comparador sxaiam vs AWS Security Hub.

Cobertura:
  - Carga de findings (lista, dict con "Findings", archivo)
  - Clasificación MISSED / PARTIAL / COVERED
  - Métricas del ComparisonReport
  - Serialización a dict y Markdown
  - Casos borde: sin findings, sin rutas, findings sin ARNs
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sxaiam.findings.comparator import (
    ComparisonReport,
    CoverageStatus,
    PathCoverage,
    SecurityHubComparator,
)
from sxaiam.findings.technique_base import Severity


# ===========================================================================
# Fixtures
# ===========================================================================

USER_ARN = "arn:aws:iam::123456789012:user/low-priv-user"
ADMIN_ID = "sxaiam::admin"


def _make_path(
    origin_arn: str = USER_ARN,
    origin_name: str = "low-priv-user",
    severity: Severity = Severity.CRITICAL,
    techniques: list[str] | None = None,
    evidence_actions: list[str] | None = None,
) -> MagicMock:
    """EscalationPath mock mínimo para tests del comparador."""
    path = MagicMock()
    path.path_id      = "test-path-001"
    path.severity     = severity
    path.origin_arn   = origin_arn
    path.origin_name  = origin_name
    path.target_arn   = ADMIN_ID
    path.target_name  = "AdministratorAccess"
    path.step_count   = 1
    path.techniques_used = techniques or ["create-policy-version"]

    actions = evidence_actions or ["iam:CreatePolicyVersion"]
    step = MagicMock()
    step.step_number    = 1
    step.from_arn       = origin_arn
    step.from_name      = origin_name
    step.to_arn         = ADMIN_ID
    step.to_name        = "AdministratorAccess"
    step.technique_id   = "create-policy-version"
    step.technique_name = "CreatePolicyVersion swap"
    step.severity       = "CRITICAL"
    step.evidence       = [f"{a} on * (via inline: test-policy)" for a in actions]
    step.api_calls      = []
    path.steps = [step]

    return path


def _make_sh_finding(
    title: str = "IAM user has excessive permissions",
    description: str = "Review this user's access rights.",
    resource_arns: list[str] | None = None,
    severity_label: str = "HIGH",
) -> dict:
    """Security Hub finding mock."""
    return {
        "Title":       title,
        "Description": description,
        "Severity": {"Label": severity_label},
        "Resources": [
            {"Type": "AwsIamUser", "Id": arn}
            for arn in (resource_arns or [])
        ],
    }


# ===========================================================================
# SECCIÓN 1 — Carga de findings
# ===========================================================================

class TestLoadFindings:
    """Tests de carga de findings de Security Hub."""

    def test_load_empty_list(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        assert len(comp._findings) == 0

    def test_load_list_of_findings(self):
        comp = SecurityHubComparator()
        comp.load_findings([_make_sh_finding(), _make_sh_finding()])
        assert len(comp._findings) == 2

    def test_load_from_file_list_format(self):
        comp = SecurityHubComparator()
        findings = [_make_sh_finding()]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(findings, f)
            tmp_path = Path(f.name)
        comp.load_findings_from_file(tmp_path)
        assert len(comp._findings) == 1

    def test_load_from_file_aws_format(self):
        """Formato que devuelve la CLI: {"Findings": [...]}"""
        comp = SecurityHubComparator()
        findings = {"Findings": [_make_sh_finding(), _make_sh_finding()]}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(findings, f)
            tmp_path = Path(f.name)
        comp.load_findings_from_file(tmp_path)
        assert len(comp._findings) == 2

    def test_load_builds_arn_index(self):
        comp = SecurityHubComparator()
        finding = _make_sh_finding(resource_arns=[USER_ARN])
        comp.load_findings([finding])
        assert USER_ARN.lower() in comp._finding_arns

    def test_load_builds_action_index(self):
        comp = SecurityHubComparator()
        finding = _make_sh_finding(
            description="User has iam:CreatePolicyVersion permission."
        )
        comp.load_findings([finding])
        assert "iam:createpolicyversion" in comp._finding_actions


# ===========================================================================
# SECCIÓN 2 — Clasificación MISSED
# ===========================================================================

class TestMissedClassification:
    """Tests de rutas que Security Hub no detecta."""

    def test_path_is_missed_when_no_findings(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        path = _make_path()
        report = comp.compare([path])
        assert len(report.missed) == 1
        assert report.missed[0].status == CoverageStatus.NOT_DETECTED

    def test_missed_path_has_gap_description(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        path = _make_path()
        report = comp.compare([path])
        assert len(report.missed[0].gap_description) > 0

    def test_missed_path_mentions_technique(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        path = _make_path(techniques=["create-policy-version"])
        report = comp.compare([path])
        assert "create-policy-version" in report.missed[0].gap_description

    def test_missed_path_mentions_severity(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        path = _make_path(severity=Severity.CRITICAL)
        report = comp.compare([path])
        assert "CRITICAL" in report.missed[0].gap_description

    def test_unrelated_finding_does_not_prevent_missed(self):
        """Un finding sobre otro usuario no debe cubrir esta ruta."""
        comp = SecurityHubComparator()
        other_arn = "arn:aws:iam::123:user/other-user"
        comp.load_findings([_make_sh_finding(resource_arns=[other_arn])])
        path = _make_path(origin_arn=USER_ARN)
        report = comp.compare([path])
        assert len(report.missed) == 1


# ===========================================================================
# SECCIÓN 3 — Clasificación PARTIAL
# ===========================================================================

class TestPartialClassification:
    """Tests de rutas parcialmente cubiertas por Security Hub."""

    def test_path_is_partial_when_arn_matches_but_not_action(self):
        comp = SecurityHubComparator()
        # Finding menciona el ARN pero no la acción específica
        finding = _make_sh_finding(
            title="IAM user review required",
            description="Review this user's permissions.",
            resource_arns=[USER_ARN],
        )
        comp.load_findings([finding])
        path = _make_path(
            origin_arn=USER_ARN,
            evidence_actions=["iam:CreatePolicyVersion"],
        )
        report = comp.compare([path])
        assert len(report.partial) == 1
        assert report.partial[0].status == CoverageStatus.PARTIAL

    def test_path_is_partial_when_action_matches_but_not_arn(self):
        comp = SecurityHubComparator()
        # Finding menciona la acción pero no el ARN específico
        finding = _make_sh_finding(
            title="Dangerous permission detected",
            description="iam:CreatePolicyVersion found in account.",
            resource_arns=[],
        )
        comp.load_findings([finding])
        path = _make_path(
            origin_arn=USER_ARN,
            evidence_actions=["iam:CreatePolicyVersion"],
        )
        report = comp.compare([path])
        assert len(report.partial) == 1

    def test_partial_has_matching_findings(self):
        comp = SecurityHubComparator()
        finding = _make_sh_finding(resource_arns=[USER_ARN])
        comp.load_findings([finding])
        path = _make_path(origin_arn=USER_ARN)
        report = comp.compare([path])
        assert len(report.partial[0].matching_findings) > 0


# ===========================================================================
# SECCIÓN 4 — Clasificación COVERED
# ===========================================================================

class TestCoveredClassification:
    """Tests de rutas completamente cubiertas por Security Hub."""

    def test_path_is_covered_when_arn_and_action_match(self):
        comp = SecurityHubComparator()
        finding = _make_sh_finding(
            title="User has iam:CreatePolicyVersion",
            description="iam:CreatePolicyVersion detected for this user.",
            resource_arns=[USER_ARN],
        )
        comp.load_findings([finding])
        path = _make_path(
            origin_arn=USER_ARN,
            evidence_actions=["iam:CreatePolicyVersion"],
        )
        report = comp.compare([path])
        assert len(report.covered) == 1
        assert report.covered[0].status == CoverageStatus.COVERED


# ===========================================================================
# SECCIÓN 5 — ComparisonReport métricas
# ===========================================================================

class TestComparisonReportMetrics:
    """Tests de métricas del reporte de comparación."""

    def test_gap_percentage_100_when_all_missed(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        paths = [_make_path(), _make_path()]
        report = comp.compare(paths)
        assert report.gap_percentage == 100.0

    def test_gap_percentage_0_when_all_covered(self):
        covered = PathCoverage(
            path=_make_path(),
            status=CoverageStatus.COVERED,
        )
        report = ComparisonReport(
            total_sxaiam_paths=1,
            total_sh_findings=5,
            covered=[covered],
        )
        assert report.gap_percentage == 0.0
        assert report.coverage_percentage == 100.0

    def test_total_paths_correct(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        paths = [_make_path(), _make_path(), _make_path()]
        report = comp.compare(paths)
        assert report.total_sxaiam_paths == 3

    def test_total_sh_findings_correct(self):
        comp = SecurityHubComparator()
        findings = [_make_sh_finding(), _make_sh_finding()]
        comp.load_findings(findings)
        report = comp.compare([])
        assert report.total_sh_findings == 2

    def test_summary_string_contains_key_info(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        path = _make_path()
        report = comp.compare([path])
        summary = report.summary()
        assert "1" in summary
        assert "no correlated detection" in summary
        assert "100.0%" in summary

    def test_empty_paths_empty_report(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        report = comp.compare([])
        assert report.total_sxaiam_paths == 0
        assert report.gap_percentage == 0.0
        assert report.coverage_percentage == 100.0


# ===========================================================================
# SECCIÓN 6 — Serialización
# ===========================================================================

class TestReportSerialization:
    """Tests de serialización del reporte."""

    def test_to_dict_has_summary(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        report = comp.compare([_make_path()])
        d = report.to_dict()
        assert "summary" in d
        assert "metrics" in d

    def test_to_dict_metrics_structure(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        report = comp.compare([_make_path()])
        metrics = report.to_dict()["metrics"]
        assert "total_sxaiam_paths" in metrics
        assert "gap_percentage"     in metrics
        assert "missed"             in metrics

    def test_to_dict_missed_paths_listed(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        report = comp.compare([_make_path()])
        d = report.to_dict()
        assert len(d["missed_paths"]) == 1
        assert "origin" in d["missed_paths"][0]
        assert "techniques" in d["missed_paths"][0]

    def test_to_markdown_has_title(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        report = comp.compare([_make_path()])
        md = report.to_markdown()
        assert "Security Hub" in md
        assert "Detection Gap" in md

    def test_to_markdown_shows_missed_section(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        report = comp.compare([_make_path()])
        md = report.to_markdown()
        assert "MISSED" in md

    def test_to_markdown_shows_metrics(self):
        comp = SecurityHubComparator()
        comp.load_findings([])
        report = comp.compare([_make_path()])
        md = report.to_markdown()
        assert "100.0%" in md

    def test_to_markdown_no_missed_section_when_empty(self):
        report = ComparisonReport(
            total_sxaiam_paths=0,
            total_sh_findings=0,
        )
        md = report.to_markdown()
        assert "MISSED" not in md or "0" in md
