"""
Regresión: los reportes AWS (JSON y Markdown) no cambian con el refactor
"make provider labels configurable".

Los archivos de referencia de tests/fixtures/aws/ se generaron con el código
ANTERIOR al refactor (commit 1c3e39e) usando ``render_reports()``. Si este test
falla, la salida AWS cambió.

Para regenerarlos (solo si el cambio de formato es intencional):

    python -c "from tests.unit.output.test_aws_report_regression import write_golden as w; w()"

Datos no deterministas que se fijan: path_id (uuid4), generated_at del JSON
y la línea "Generated:" del Markdown.
"""

from __future__ import annotations

import re
from pathlib import Path

import networkx as nx
import pytest

from sxaiam.findings.technique_base import Severity, TechniqueMatch
from sxaiam.graph.nodes import AdminNode, RoleNode, UserNode
from sxaiam.graph.pathfinder import PathFinder
from sxaiam.output import json_exporter
from sxaiam.output.json_exporter import JSONExporter
from sxaiam.output.markdown_exporter import MarkdownExporter

GOLDEN_DIR = Path(__file__).parents[2] / "fixtures" / "aws"
GOLDEN_JSON = GOLDEN_DIR / "golden_report.json"
GOLDEN_MD = GOLDEN_DIR / "golden_report.md"

ACCOUNT = "123456789012"
FIXED_NOW = "2026-01-01T00:00:00Z"
_GENERATED_RE = re.compile(r"^> \*\*Generated:\*\* .*$", re.MULTILINE)

ALICE = f"arn:aws:iam::{ACCOUNT}:user/alice"
BOB = f"arn:aws:iam::{ACCOUNT}:user/bob"
DEPLOY = f"arn:aws:iam::{ACCOUNT}:role/deploy"


def _match(origin: str, name: str, technique: str, severity: Severity) -> TechniqueMatch:
    return TechniqueMatch(
        technique_id=technique,
        technique_name=technique,
        severity=severity,
        origin_arn=origin,
        origin_name=name,
        target_arn="sxaiam::admin",
        target_name="AdministratorAccess",
        description="test",
        evidence=[f"iam:{technique} on * (via inline: {name}-policy)"],
        attack_steps=[f"aws iam {technique} --example {name}"],
    )


def _edge(graph: nx.DiGraph, src: str, dst: str, match: TechniqueMatch | None,
          technique: str, severity: str) -> None:
    # Mismo formato de atributos que AttackGraph._build_technique_edges / _build_trust_edges
    graph.add_edge(
        src, dst,
        technique=technique,
        severity=severity,
        evidence=[{
            "action": f"iam:{technique}",
            "resource": "*",
            "source_type": "policy",
            "source_name": technique,
            "source_arn": src,
        }],
        attack_steps=match.attack_steps if match else [f"aws sts assume-role --role-arn {dst}"],
        technique_match=match,
    )


def build_aws_graph() -> nx.DiGraph:
    """alice → admin (CRITICAL); deploy → admin (HIGH); bob → deploy (trust) → admin (HIGH)."""
    g = nx.DiGraph()
    admin = AdminNode()
    g.add_node(admin.node_id, node=admin)
    for node in (
        UserNode(node_id=ALICE, label="alice", account_id=ACCOUNT),
        UserNode(node_id=BOB, label="bob", account_id=ACCOUNT),
        RoleNode(node_id=DEPLOY, label="deploy", account_id=ACCOUNT, has_trust_policy=True),
    ):
        g.add_node(node.node_id, node=node)

    _edge(g, ALICE, admin.node_id, _match(ALICE, "alice", "attach-policy", Severity.CRITICAL),
          "attach-policy", "CRITICAL")
    _edge(g, BOB, DEPLOY, None, "trust_policy", "INFO")
    _edge(g, DEPLOY, admin.node_id, _match(DEPLOY, "deploy", "create-policy-version",
                                           Severity.HIGH), "create-policy-version", "HIGH")
    return g


def render_reports() -> tuple[str, str]:
    """Devuelve (json, markdown) del grafo AWS fijo, con datos no deterministas fijados."""
    paths = PathFinder(build_aws_graph()).find_all_paths()
    paths.sort(key=lambda p: (p.origin_arn, p.step_count))
    for i, path in enumerate(paths, start=1):
        path.path_id = f"00000000-0000-0000-0000-{i:012d}"

    original_now = json_exporter._now_iso
    json_exporter._now_iso = lambda: FIXED_NOW
    try:
        json_text = JSONExporter(account_id=ACCOUNT).to_json(paths)
    finally:
        json_exporter._now_iso = original_now

    md_text = _GENERATED_RE.sub("> **Generated:** <fixed>  ", MarkdownExporter(account_id=ACCOUNT)
                                .to_markdown(paths))
    return json_text, md_text


def write_golden() -> None:
    """Escribe los archivos de referencia con saltos de línea LF."""
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    json_text, md_text = render_reports()
    GOLDEN_JSON.write_bytes(json_text.encode("utf-8") + b"\n")
    GOLDEN_MD.write_bytes(md_text.encode("utf-8") + b"\n")


def _read_golden(path: Path) -> str:
    # Normaliza CRLF por si el checkout en Windows convirtió los saltos de línea
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n").removesuffix("\n")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def reports() -> tuple[str, str]:
    return render_reports()


def test_scenario_paths() -> None:
    # alice → admin, deploy → admin, bob → deploy → admin
    paths = PathFinder(build_aws_graph()).find_all_paths()
    assert len(paths) == 3


def test_aws_json_report_unchanged(reports: tuple[str, str]) -> None:
    assert reports[0] == _read_golden(GOLDEN_JSON)


def test_aws_markdown_report_unchanged(reports: tuple[str, str]) -> None:
    assert reports[1] == _read_golden(GOLDEN_MD)


def test_golden_files_are_lf() -> None:
    for path in (GOLDEN_JSON, GOLDEN_MD):
        assert b"\r\n" not in path.read_bytes(), f"{path.name} tiene CRLF"


# ---------------------------------------------------------------------------
# Etiquetas configurables (valores no AWS)
# ---------------------------------------------------------------------------

def test_admin_node_default_label() -> None:
    assert AdminNode().label == "AdministratorAccess"


def test_admin_node_custom_label_keeps_identity() -> None:
    custom = AdminNode(label="Project Owner")
    assert custom.label == "Project Owner"
    assert custom.node_id == AdminNode().node_id == "sxaiam::admin"
    assert custom.node_type == AdminNode().node_type
    assert custom == AdminNode()


def test_custom_admin_label_reaches_paths() -> None:
    g = build_aws_graph()
    g.nodes["sxaiam::admin"]["node"] = AdminNode(label="Project Owner")
    assert {p.target_name for p in PathFinder(g).find_all_paths()} == {"Project Owner"}


def test_markdown_custom_labels() -> None:
    paths = PathFinder(build_aws_graph()).find_all_paths()
    md = MarkdownExporter(
        account_id="proj-1", scope_label="Project", footer_tagline="GCP tagline",
    ).to_markdown(paths)
    assert "> **Project:** `proj-1`" in md
    assert md.endswith("— GCP tagline*")
    assert "**Account:**" not in md


def test_json_custom_scope_key_keeps_position() -> None:
    paths = PathFinder(build_aws_graph()).find_all_paths()
    metadata = JSONExporter(account_id="proj-1", scope_key="project_id").to_dict(paths)["metadata"]
    assert list(metadata)[:3] == ["generated_at", "sxaiam_version", "project_id"]
    assert metadata["project_id"] == "proj-1"
    assert "account_id" not in metadata
