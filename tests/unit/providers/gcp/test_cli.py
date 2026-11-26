"""
Tests for sxaiam.providers.gcp.cli — ``sxaiam gcp scan`` vía CliRunner de Typer.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sxaiam.cli import app
from sxaiam.findings.technique_base import Severity, TechniqueMatch
from sxaiam.providers.gcp.techniques import GCPEscalationTechnique, GCPTechniqueRegistry

FIXTURE = Path(__file__).parents[3] / "fixtures" / "gcp" / "vulnerable_project.json"
DEPLOYER = "serviceAccount:deployer@acme-poc-123456.iam.gserviceaccount.com"

runner = CliRunner()


def run(*args: str) -> Any:
    return runner.invoke(app, ["gcp", "scan", *args], env={"COLUMNS": "200"})


def flat(text: str) -> str:
    """Colapsa espacios y saltos de línea (Rich puede partir líneas largas)."""
    return " ".join(text.split())


def write_snapshot(tmp_path: Path, raw: dict[str, Any]) -> Path:
    path = tmp_path / "snap.json"
    path.write_text(json.dumps({"project_id": "p", **raw}), encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def json_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[Any, dict[str, Any]]:
    out = tmp_path_factory.mktemp("gcp") / "report.json"
    result = run("--snapshot", str(FIXTURE), "--output", str(out))
    return result, json.loads(out.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Comando montado
# ---------------------------------------------------------------------------

def test_root_help_lists_aws_and_gcp_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("scan", "report", "compare", "gcp"):
        assert command in result.output


def test_gcp_help_lists_scan() -> None:
    result = runner.invoke(app, ["gcp", "--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


# ---------------------------------------------------------------------------
# Fixture → JSON
# ---------------------------------------------------------------------------

def test_scan_json_exit_code(json_run: tuple[Any, dict[str, Any]]) -> None:
    result, _ = json_run
    assert result.exit_code == 0, result.output


def test_scan_json_report(json_run: tuple[Any, dict[str, Any]]) -> None:
    _, report = json_run
    assert report["metadata"]["project_id"] == "acme-poc-123456"
    assert "account_id" not in report["metadata"]
    assert report["metadata"]["total_paths"] == 2
    assert report["metadata"]["critical"] == 1
    assert report["metadata"]["high"] == 1
    by_origin = {p["origin"]["arn"]: p for p in report["paths"]}
    assert set(by_origin) == {"user:alice@acme-poc.example", "user:bob@acme-poc.example"}
    assert by_origin["user:bob@acme-poc.example"]["severity"] == "HIGH"
    assert by_origin["user:bob@acme-poc.example"]["target"]["name"] == "Project Owner (roles/owner)"
    assert DEPLOYER not in by_origin   # origen ya-admin filtrado


def test_scan_progress_output(json_run: tuple[Any, dict[str, Any]]) -> None:
    out = flat(json_run[0].output)
    assert "4 project bindings, 3 service accounts - project acme-poc-123456" in out
    assert "6 principals resolved, 1 binding(s) ignored" in out
    assert "7 nodes, 4 edges - 2 escalation path(s) found" in out
    assert "1 from already-admin origins filtered" in out


def test_summary_table_reused(json_run: tuple[Any, dict[str, Any]]) -> None:
    out = json_run[0].output
    assert "Escalation Paths Found" in out
    assert "alice@acme-poc.example" in out
    assert "bob@acme-poc.example" in out


def test_summary_ignored_bindings(json_run: tuple[Any, dict[str, Any]]) -> None:
    out = flat(json_run[0].output)
    assert "1 binding(s) ignored (not evaluated)" in out
    assert "conditional binding (1)" in out
    assert (
        "user:dave@acme-poc.example roles/resourcemanager.projectIamAdmin "
        "on projects/acme-poc-123456"
    ) in out


def test_summary_already_admin(json_run: tuple[Any, dict[str, Any]]) -> None:
    out = flat(json_run[0].output)
    assert "Already admin (roles/owner, not escalation paths): 1" in out
    assert DEPLOYER in out


def test_no_raw_logger_warnings(json_run: tuple[Any, dict[str, Any]]) -> None:
    # Las advertencias salen por Rich en ASCII, no por el last-resort handler de logging
    result, _ = json_run
    combined = result.output + (result.stderr if result.stderr_bytes is not None else "")
    assert "condicional" not in combined
    assert "�" not in combined


# ---------------------------------------------------------------------------
# Fixture → Markdown
# ---------------------------------------------------------------------------

def test_scan_markdown(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    result = run("--snapshot", str(FIXTURE), "--output", str(out), "--format", "markdown")
    assert result.exit_code == 0, result.output
    md = out.read_text(encoding="utf-8")
    assert "> **Project:** `acme-poc-123456`" in md
    assert "GCP IAM Attack Path Analysis (PoC)*" in md
    assert "→ `Project Owner (roles/owner)`" in md
    # Ningún texto AWS fijo en el reporte GCP
    for aws_text in ("**Account:**", "AdministratorAccess", "AWS IAM Attack Path Analysis"):
        assert aws_text not in md
    assert "**2 privilege escalation path(s) found.**" in md
    assert "gcloud auth print-access-token --impersonate-service-account=" in md
    assert "via role roles/iam.serviceAccountTokenCreator" in md


# ---------------------------------------------------------------------------
# Snapshots sintéticos
# ---------------------------------------------------------------------------

def test_no_ignored_bindings(tmp_path: Path) -> None:
    snap = write_snapshot(tmp_path, {"project_iam_policy": {"bindings": [
        {"role": "roles/viewer", "members": ["user:a@x"]},
    ]}})
    result = run("--snapshot", str(snap), "--output", str(tmp_path / "r.json"))
    assert result.exit_code == 0, result.output
    assert "No bindings ignored." in result.output
    assert "No escalation paths found." in result.output
    assert "Already admin" not in result.output


def test_ignored_bindings_grouped_by_reason(tmp_path: Path) -> None:
    snap = write_snapshot(tmp_path, {"project_iam_policy": {"bindings": [
        {"role": "roles/viewer", "members": ["deleted:user:old@x?uid=1", "principal://x/y"]},
        {"role": "projects/p/roles/custom", "members": ["user:a@x"]},
        {"role": "roles/owner", "members": ["user:b@x", "user:c@x"],
         "condition": {"title": "t", "expression": "true"}},
    ]}})
    result = run("--snapshot", str(snap), "--output", str(tmp_path / "r.json"))
    assert result.exit_code == 0, result.output
    out = flat(result.output)
    assert "5 binding(s) ignored (not evaluated)" in out
    # Orden fijo de motivos
    positions = [out.index(s) for s in (
        "conditional binding (2)",
        "deleted member (1)",
        "unsupported member type (1)",
        "unsupported role (1)",
    )]
    assert positions == sorted(positions)
    assert "- projects/p/roles/custom on projects/p" in out


def test_rich_markup_in_data_is_escaped(tmp_path: Path) -> None:
    snap = write_snapshot(tmp_path, {"project_iam_policy": {"bindings": [
        {"role": "roles/viewer", "members": ["deleted:user:[bold]x[/bold]@x"]},
    ]}})
    result = run("--snapshot", str(snap), "--output", str(tmp_path / "r.json"))
    assert result.exit_code == 0, result.output
    assert "deleted:user:[bold]x[/bold]@x" in result.output


class _GhostTechnique(GCPEscalationTechnique):
    technique_id = "gcp-test-ghost"  # type: ignore[assignment]
    name = "ghost"  # type: ignore[assignment]
    severity = Severity.HIGH  # type: ignore[assignment]
    required_permissions: list[str] = []  # type: ignore[assignment]
    description = "test"  # type: ignore[assignment]

    def check(self, principal, snapshot):  # type: ignore[no-untyped-def]
        return [TechniqueMatch(
            technique_id=self.technique_id, technique_name=self.name, severity=self.severity,
            origin_arn=principal.member, origin_name=principal.name,
            target_arn="serviceAccount:ghost@p.iam.gserviceaccount.com", target_name="ghost",
            description="",
        )]


def test_dropped_edges_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(GCPTechniqueRegistry._techniques, "gcp-test-ghost", _GhostTechnique())
    snap = write_snapshot(tmp_path, {"project_iam_policy": {"bindings": [
        {"role": "roles/viewer", "members": ["user:a@x"]},
    ]}})
    result = run("--snapshot", str(snap), "--output", str(tmp_path / "r.json"))
    assert result.exit_code == 0, result.output
    out = flat(result.output)
    assert "1 edge(s) dropped (target not in graph)" in out
    assert "gcp-test-ghost: user:a@x -> serviceAccount:ghost@p.iam.gserviceaccount.com" in out


# ---------------------------------------------------------------------------
# Errores
# ---------------------------------------------------------------------------

def test_snapshot_not_found(tmp_path: Path) -> None:
    result = run("--snapshot", str(tmp_path / "nope.json"), "--output", str(tmp_path / "r.json"))
    assert result.exit_code == 1
    assert "Snapshot not found" in result.output


def test_invalid_snapshot(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"project_iam_policy": {}}', encoding="utf-8")
    result = run("--snapshot", str(bad), "--output", str(tmp_path / "r.json"))
    assert result.exit_code == 1
    assert "Snapshot load failed" in result.output
    assert not (tmp_path / "r.json").exists()


def test_unknown_format(tmp_path: Path) -> None:
    result = run("--snapshot", str(FIXTURE), "--output", str(tmp_path / "r"), "--format", "graphml")
    assert result.exit_code == 1
    assert "Unknown format" in result.output


def test_snapshot_option_required() -> None:
    result = run()
    assert result.exit_code == 2
