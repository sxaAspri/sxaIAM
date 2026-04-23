"""
tests/unit/output/test_outputs.py

Tests unitarios de los tres exporters de sxaiam.output.

Cobertura:
  - JSONExporter:     to_dict, to_json, export a archivo, metadata, estructura
  - MarkdownExporter: to_markdown, secciones, severidad, rutas vacías
  - GraphMLExporter:  to_graphml_string, nodos, aristas, atributos

Todos los tests usan fixtures mínimas construidas a mano — sin AWS,
sin credenciales, sin archivos reales salvo los tests de export a disco.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import networkx as nx
import pytest

from sxaiam.findings.technique_base import Severity
from sxaiam.graph.nodes import AdminNode, NODE_TYPE_ADMIN, NODE_TYPE_USER, UserNode
from sxaiam.output.json_exporter import JSONExporter
from sxaiam.output.markdown_exporter import MarkdownExporter
from sxaiam.output.graphml_exporter import GraphMLExporter


# ===========================================================================
# Fixtures
# ===========================================================================

def _make_path(
    path_id: str = "test-path-001",
    severity: Severity = Severity.CRITICAL,
    origin_arn: str = "arn:aws:iam::123:user/alice",
    origin_name: str = "alice",
    target_arn: str = "sxaiam::admin",
    target_name: str = "AdministratorAccess",
    techniques: list[str] | None = None,
    num_steps: int = 1,
) -> MagicMock:
    """EscalationPath mock para tests."""
    path = MagicMock()
    path.path_id      = path_id
    path.severity     = severity
    path.origin_arn   = origin_arn
    path.origin_name  = origin_name
    path.target_arn   = target_arn
    path.target_name  = target_name
    path.step_count   = num_steps
    path.techniques_used = techniques or ["create-policy-version"]
    path.all_evidence = ["iam:CreatePolicyVersion on * (via inline: test-policy)"]

    steps = []
    for i in range(1, num_steps + 1):
        step = MagicMock()
        step.step_number   = i
        step.from_arn      = origin_arn
        step.from_name     = origin_name
        step.to_arn        = target_arn
        step.to_name       = target_name
        step.technique_id  = "create-policy-version"
        step.technique_name = "CreatePolicyVersion swap"
        step.severity      = "CRITICAL"
        step.evidence      = ["iam:CreatePolicyVersion on * (via inline: test-policy)"]
        step.api_calls     = ["aws iam create-policy-version --policy-arn arn:... --set-as-default"]
        steps.append(step)

    path.steps = steps
    return path


def _make_graph_with_edge() -> nx.DiGraph:
    """DiGraph mínimo con un nodo usuario, un AdminNode y una arista."""
    G = nx.DiGraph()

    user_arn = "arn:aws:iam::123:user/alice"
    admin_id = "sxaiam::admin"

    user_node  = UserNode(node_id=user_arn, label="alice", account_id="123")
    admin_node = AdminNode()

    G.add_node(user_arn, node=user_node)
    G.add_node(admin_id, node=admin_node)

    G.add_edge(
        user_arn,
        admin_id,
        technique="create-policy-version",
        severity="CRITICAL",
        evidence=[{"action": "iam:CreatePolicyVersion", "resource": "*",
                   "source_type": "inline", "source_name": "test-policy",
                   "source_arn": ""}],
        attack_steps=["aws iam create-policy-version ..."],
        technique_match=None,
    )
    return G


# ===========================================================================
# SECCIÓN 1 — JSONExporter
# ===========================================================================

class TestJSONExporter:
    """Tests del exportador JSON."""

    def test_to_dict_has_metadata(self):
        exporter = JSONExporter(account_id="123456789012")
        data = exporter.to_dict([])
        assert "metadata" in data
        assert data["metadata"]["account_id"] == "123456789012"
        assert data["metadata"]["total_paths"] == 0

    def test_to_dict_has_paths_key(self):
        exporter = JSONExporter()
        data = exporter.to_dict([])
        assert "paths" in data
        assert data["paths"] == []

    def test_to_dict_counts_by_severity(self):
        exporter = JSONExporter()
        paths = [
            _make_path(severity=Severity.CRITICAL),
            _make_path(severity=Severity.CRITICAL),
            _make_path(severity=Severity.HIGH),
        ]
        data = exporter.to_dict(paths)
        assert data["metadata"]["critical"] == 2
        assert data["metadata"]["high"] == 1
        assert data["metadata"]["total_paths"] == 3

    def test_to_dict_serializes_path_fields(self):
        exporter = JSONExporter()
        path = _make_path(path_id="abc-123", severity=Severity.CRITICAL)
        data = exporter.to_dict([path])
        serialized = data["paths"][0]

        assert serialized["path_id"]        == "abc-123"
        assert serialized["severity"]       == "CRITICAL"
        assert serialized["origin"]["arn"]  == "arn:aws:iam::123:user/alice"
        assert serialized["origin"]["name"] == "alice"
        assert serialized["target"]["arn"]  == "sxaiam::admin"
        assert serialized["step_count"]     == 1

    def test_to_dict_serializes_steps(self):
        exporter = JSONExporter()
        path = _make_path(num_steps=1)
        data = exporter.to_dict([path])
        steps = data["paths"][0]["steps"]

        assert len(steps) == 1
        assert steps[0]["step"]      == 1
        assert steps[0]["technique"] == "CreatePolicyVersion swap"
        assert steps[0]["severity"]  == "CRITICAL"
        assert len(steps[0]["evidence"]) == 1

    def test_to_json_returns_valid_json_string(self):
        exporter = JSONExporter()
        path = _make_path()
        result = exporter.to_json([path])
        parsed = json.loads(result)
        assert "metadata" in parsed
        assert "paths" in parsed

    def test_to_json_is_pretty_printed(self):
        exporter = JSONExporter()
        result = exporter.to_json([], indent=2)
        assert "\n" in result

    def test_export_writes_file(self):
        exporter = JSONExporter(account_id="123")
        path = _make_path()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            exporter.export([path], output)
            assert output.exists()
            data = json.loads(output.read_text())
            assert data["metadata"]["total_paths"] == 1

    def test_export_creates_parent_dirs(self):
        exporter = JSONExporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "subdir" / "deep" / "report.json"
            exporter.export([], output)
            assert output.exists()

    def test_metadata_has_generated_at(self):
        exporter = JSONExporter()
        data = exporter.to_dict([])
        assert "generated_at" in data["metadata"]
        assert "Z" in data["metadata"]["generated_at"]

    def test_empty_paths_produces_valid_output(self):
        exporter = JSONExporter()
        data = exporter.to_dict([])
        assert data["metadata"]["total_paths"] == 0
        assert data["paths"] == []


# ===========================================================================
# SECCIÓN 2 — MarkdownExporter
# ===========================================================================

class TestMarkdownExporter:
    """Tests del exportador Markdown."""

    def test_to_markdown_returns_string(self):
        exporter = MarkdownExporter()
        result = exporter.to_markdown([])
        assert isinstance(result, str)
        assert len(result) > 0

    def test_to_markdown_has_title(self):
        exporter = MarkdownExporter()
        result = exporter.to_markdown([])
        assert "sxaiam" in result
        assert "IAM Privilege Escalation Report" in result

    def test_to_markdown_shows_account_id(self):
        exporter = MarkdownExporter(account_id="999888777666")
        result = exporter.to_markdown([])
        assert "999888777666" in result

    def test_to_markdown_executive_summary_present(self):
        exporter = MarkdownExporter()
        result = exporter.to_markdown([])
        assert "Executive Summary" in result

    def test_to_markdown_shows_zero_paths(self):
        exporter = MarkdownExporter()
        result = exporter.to_markdown([])
        assert "0" in result

    def test_to_markdown_shows_path_count(self):
        exporter = MarkdownExporter()
        paths = [_make_path(), _make_path()]
        result = exporter.to_markdown(paths)
        assert "2" in result

    def test_to_markdown_shows_severity(self):
        exporter = MarkdownExporter()
        path = _make_path(severity=Severity.CRITICAL)
        result = exporter.to_markdown([path])
        assert "CRITICAL" in result

    def test_to_markdown_shows_origin_name(self):
        exporter = MarkdownExporter()
        path = _make_path(origin_name="low-priv-user")
        result = exporter.to_markdown([path])
        assert "low-priv-user" in result

    def test_to_markdown_shows_technique(self):
        exporter = MarkdownExporter()
        path = _make_path()
        result = exporter.to_markdown([path])
        assert "CreatePolicyVersion" in result

    def test_to_markdown_shows_evidence(self):
        exporter = MarkdownExporter()
        path = _make_path()
        result = exporter.to_markdown([path])
        assert "iam:CreatePolicyVersion" in result

    def test_to_markdown_shows_api_calls(self):
        exporter = MarkdownExporter()
        path = _make_path()
        result = exporter.to_markdown([path])
        assert "aws iam create-policy-version" in result

    def test_to_markdown_shows_remediation(self):
        exporter = MarkdownExporter()
        path = _make_path()
        result = exporter.to_markdown([path])
        assert "Remediation" in result

    def test_to_markdown_critical_before_high(self):
        exporter = MarkdownExporter()
        critical = _make_path(origin_name="alice", severity=Severity.CRITICAL)
        high     = _make_path(origin_name="bob",   severity=Severity.HIGH)
        result = exporter.to_markdown([high, critical])
        assert result.index("CRITICAL") < result.index("HIGH")

    def test_export_writes_file(self):
        exporter = MarkdownExporter()
        path = _make_path()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.md"
            exporter.export([path], output)
            assert output.exists()
            content = output.read_text()
            assert "sxaiam" in content

    def test_export_creates_parent_dirs(self):
        exporter = MarkdownExporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "reports" / "report.md"
            exporter.export([], output)
            assert output.exists()

    def test_no_paths_shows_clean_message(self):
        exporter = MarkdownExporter()
        result = exporter.to_markdown([])
        assert "No privilege escalation paths found" in result


# ===========================================================================
# SECCIÓN 3 — GraphMLExporter
# ===========================================================================

class TestGraphMLExporter:
    """Tests del exportador GraphML."""

    def test_to_graphml_string_returns_string(self):
        exporter = GraphMLExporter()
        G = _make_graph_with_edge()
        result = exporter.to_graphml_string(G)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_graphml_is_valid_xml(self):
        import xml.etree.ElementTree as ET
        exporter = GraphMLExporter()
        G = _make_graph_with_edge()
        result = exporter.to_graphml_string(G)
        # No debe lanzar excepción
        root = ET.fromstring(result)
        assert root is not None

    def test_graphml_contains_graphml_tag(self):
        exporter = GraphMLExporter()
        G = _make_graph_with_edge()
        result = exporter.to_graphml_string(G)
        assert "graphml" in result.lower()

    def test_graphml_contains_nodes(self):
        exporter = GraphMLExporter()
        G = _make_graph_with_edge()
        result = exporter.to_graphml_string(G)
        assert "alice" in result
        assert "AdministratorAccess" in result

    def test_graphml_contains_node_types(self):
        exporter = GraphMLExporter()
        G = _make_graph_with_edge()
        result = exporter.to_graphml_string(G)
        assert NODE_TYPE_USER  in result
        assert NODE_TYPE_ADMIN in result

    def test_graphml_contains_edge_technique(self):
        exporter = GraphMLExporter()
        G = _make_graph_with_edge()
        result = exporter.to_graphml_string(G)
        assert "create-policy-version" in result

    def test_graphml_contains_edge_severity(self):
        exporter = GraphMLExporter()
        G = _make_graph_with_edge()
        result = exporter.to_graphml_string(G)
        assert "CRITICAL" in result

    def test_export_writes_file(self):
        exporter = GraphMLExporter()
        G = _make_graph_with_edge()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.graphml"
            exporter.export(G, output)
            assert output.exists()
            content = output.read_text()
            assert "graphml" in content.lower()

    def test_export_creates_parent_dirs(self):
        exporter = GraphMLExporter()
        G = nx.DiGraph()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "graphs" / "report.graphml"
            exporter.export(G, output)
            assert output.exists()

    def test_empty_graph_exports_cleanly(self):
        exporter = GraphMLExporter()
        G = nx.DiGraph()
        result = exporter.to_graphml_string(G)
        assert isinstance(result, str)
        assert "graphml" in result.lower()

    def test_node_without_iam_node_object_handled(self):
        """Nodos sin atributo 'node' no deben causar error."""
        exporter = GraphMLExporter()
        G = nx.DiGraph()
        G.add_node("bare-node")
        result = exporter.to_graphml_string(G)
        assert "bare-node" in result
