"""
Tests for sxaiam.providers.gcp.builder

Verificación de la Fase 4: el PathFinder AWS, sin cambios, recorre el grafo
GCP. Sobre el fixture: 3 rutas crudas, 2 tras filtrar orígenes ya-admin,
bob en HIGH. Snapshots sintéticos para cadenas y principales especiales.
"""

from pathlib import Path
from typing import Any

import networkx as nx
import pytest

from sxaiam.findings.escalation_path import EscalationPath
from sxaiam.findings.technique_base import Severity, TechniqueMatch
from sxaiam.graph.nodes import NODE_TYPE_ADMIN
from sxaiam.graph.pathfinder import PathFinder
from sxaiam.providers.gcp.builder import (
    ALREADY_ADMIN,
    NODE_TYPE_GCP_SERVICE_ACCOUNT,
    NODE_TYPE_GCP_USER,
    GCPAttackGraph,
    filter_already_admin,
    is_already_admin_node,
)
from sxaiam.providers.gcp.loader import load_snapshot, parse_snapshot
from sxaiam.providers.gcp.resolver import GCPResolver

FIXTURE = Path(__file__).parents[3] / "fixtures" / "gcp" / "vulnerable_project.json"

ADMIN = "sxaiam::admin"
DEPLOYER = "serviceAccount:deployer@acme-poc-123456.iam.gserviceaccount.com"
READER = "serviceAccount:reader@acme-poc-123456.iam.gserviceaccount.com"
CI_RUNNER = "serviceAccount:ci-runner@acme-poc-123456.iam.gserviceaccount.com"
ALICE = "user:alice@acme-poc.example"
BOB = "user:bob@acme-poc.example"
CAROL = "user:carol@acme-poc.example"


def build(raw_or_path: Any) -> nx.DiGraph:
    snap = load_snapshot(raw_or_path) if isinstance(raw_or_path, Path) else parse_snapshot(
        {"project_id": "p", **raw_or_path}
    )
    return GCPAttackGraph().build(snap, GCPResolver(snap).resolve_all())


def chain(path: EscalationPath) -> list[str]:
    return [s.from_arn for s in path.steps] + [path.steps[-1].to_arn]


@pytest.fixture(scope="module")
def graph() -> nx.DiGraph:
    return build(FIXTURE)


@pytest.fixture(scope="module")
def raw_paths(graph: nx.DiGraph) -> list[EscalationPath]:
    return PathFinder(graph).find_all_paths()


@pytest.fixture(scope="module")
def paths(raw_paths: list[EscalationPath], graph: nx.DiGraph) -> list[EscalationPath]:
    return filter_already_admin(raw_paths, graph)


# ---------------------------------------------------------------------------
# Nodos
# ---------------------------------------------------------------------------

def test_nodes(graph: nx.DiGraph) -> None:
    # dave no tiene nodo: su único binding es condicional
    assert set(graph.nodes) == {ADMIN, ALICE, BOB, CAROL, DEPLOYER, READER, CI_RUNNER}


def test_node_types(graph: nx.DiGraph) -> None:
    assert graph.nodes[ADMIN]["node"].node_type == NODE_TYPE_ADMIN
    assert graph.nodes[ADMIN]["node"].label == "Project Owner (roles/owner)"
    assert graph.nodes[ALICE]["node"].node_type == NODE_TYPE_GCP_USER
    assert graph.nodes[DEPLOYER]["node"].node_type == NODE_TYPE_GCP_SERVICE_ACCOUNT


def test_node_labels_and_project(graph: nx.DiGraph) -> None:
    node = graph.nodes[DEPLOYER]["node"]
    assert node.label == "deployer@acme-poc-123456.iam.gserviceaccount.com"
    assert node.account_id == "acme-poc-123456"
    assert graph.nodes[ALICE]["node"].label == "alice@acme-poc.example"


# ---------------------------------------------------------------------------
# Aristas
# ---------------------------------------------------------------------------

def test_edges(graph: nx.DiGraph) -> None:
    edges = {(u, v): (d["technique"], d["severity"]) for u, v, d in graph.edges(data=True)}
    assert edges == {
        (ALICE, ADMIN): ("gcp-set-iam-policy", "CRITICAL"),
        (BOB, DEPLOYER): ("gcp-sa-impersonation", "HIGH"),
        (CI_RUNNER, READER): ("gcp-sa-impersonation", "HIGH"),
        (DEPLOYER, ADMIN): (ALREADY_ADMIN, "INFO"),
    }


def test_already_admin_edge(graph: nx.DiGraph) -> None:
    edge = graph.edges[DEPLOYER, ADMIN]
    assert edge["technique_match"] is None
    assert edge["attack_steps"] == []
    assert edge["evidence"] == [f"{DEPLOYER} holds roles/owner on projects/acme-poc-123456"]


def test_admin_principal_not_evaluated_against_techniques(graph: nx.DiGraph) -> None:
    # owner tiene setIamPolicy: si se evaluara, la arista sería CRITICAL
    assert graph.out_degree(DEPLOYER) == 1
    assert graph.edges[DEPLOYER, ADMIN]["severity"] == "INFO"


def test_technique_edges_carry_match(graph: nx.DiGraph) -> None:
    match = graph.edges[ALICE, ADMIN]["technique_match"]
    assert isinstance(match, TechniqueMatch)
    assert match.technique_id == "gcp-set-iam-policy"
    assert all(isinstance(e, str) for e in graph.edges[ALICE, ADMIN]["evidence"])


def test_is_already_admin_node(graph: nx.DiGraph) -> None:
    assert is_already_admin_node(graph, DEPLOYER)
    assert not is_already_admin_node(graph, ALICE)   # arista a admin, pero por técnica
    assert not is_already_admin_node(graph, CAROL)


# ---------------------------------------------------------------------------
# Rutas sobre el fixture (PathFinder sin cambios)
# ---------------------------------------------------------------------------

def test_three_raw_paths(raw_paths: list[EscalationPath]) -> None:
    assert sorted(map(chain, raw_paths)) == sorted([
        [ALICE, ADMIN],
        [BOB, DEPLOYER, ADMIN],
        [DEPLOYER, ADMIN],
    ])


def test_two_paths_after_filter(paths: list[EscalationPath]) -> None:
    assert sorted(map(chain, paths)) == sorted([
        [ALICE, ADMIN],
        [BOB, DEPLOYER, ADMIN],
    ])


def test_alice_path_critical_one_step(paths: list[EscalationPath]) -> None:
    [alice] = [p for p in paths if p.steps[0].from_arn == ALICE]
    assert alice.severity is Severity.CRITICAL
    assert len(alice.steps) == 1


def test_bob_path_is_high(paths: list[EscalationPath]) -> None:
    [bob] = [p for p in paths if p.steps[0].from_arn == BOB]
    assert bob.severity is Severity.HIGH
    assert len(bob.steps) == 2
    assert [s.technique_id for s in bob.steps] == ["gcp-sa-impersonation", ALREADY_ADMIN]


def test_path_step_evidence_is_readable(paths: list[EscalationPath]) -> None:
    [bob] = [p for p in paths if p.steps[0].from_arn == BOB]
    assert any("roles/iam.serviceAccountTokenCreator" in e for e in bob.steps[0].evidence)


def test_ci_runner_edge_not_in_any_path(raw_paths: list[EscalationPath]) -> None:
    assert not any(CI_RUNNER in chain(p) or READER in chain(p) for p in raw_paths)


# ---------------------------------------------------------------------------
# Snapshots sintéticos
# ---------------------------------------------------------------------------

def test_chain_through_project_iam_admin_sa_is_critical() -> None:
    # eve → (T2) → SA con projectIamAdmin → (T1) → admin
    sa = "serviceAccount:iam-bot@p.iam.gserviceaccount.com"
    graph = build({
        "project_iam_policy": {"bindings": [
            {"role": "roles/resourcemanager.projectIamAdmin", "members": [sa]},
        ]},
        "service_accounts": [{
            "email": "iam-bot@p.iam.gserviceaccount.com",
            "iam_policy": {"bindings": [
                {"role": "roles/iam.serviceAccountTokenCreator", "members": ["user:eve@x"]},
            ]},
        }],
    })
    [path] = PathFinder(graph).find_paths_from("user:eve@x")
    assert chain(path) == ["user:eve@x", sa, ADMIN]
    assert len(path.steps) == 2
    assert path.severity is Severity.CRITICAL
    assert [s.severity for s in path.steps] == ["HIGH", "CRITICAL"]


def test_sa_to_sa_chain() -> None:
    # eve → a → b (owner) → admin: 3 pasos, HIGH
    a = "serviceAccount:a@p.iam.gserviceaccount.com"
    b = "serviceAccount:b@p.iam.gserviceaccount.com"
    token_creator = "roles/iam.serviceAccountTokenCreator"
    graph = build({
        "project_iam_policy": {"bindings": [{"role": "roles/owner", "members": [b]}]},
        "service_accounts": [
            {"email": "a@p.iam.gserviceaccount.com", "iam_policy": {"bindings": [
                {"role": token_creator, "members": ["user:eve@x"]}]}},
            {"email": "b@p.iam.gserviceaccount.com", "iam_policy": {"bindings": [
                {"role": token_creator, "members": [a]}]}},
        ],
    })
    paths = filter_already_admin(PathFinder(graph).find_all_paths(), graph)
    assert sorted(map(chain, paths)) == sorted([
        ["user:eve@x", a, b, ADMIN],
        [a, b, ADMIN],
    ])
    assert all(p.severity is Severity.HIGH for p in paths)


def test_all_users_with_project_iam_admin() -> None:
    graph = build({"project_iam_policy": {"bindings": [
        {"role": "roles/resourcemanager.projectIamAdmin", "members": ["allUsers"]},
    ]}})
    assert graph.nodes["allUsers"]["node"].node_type == "gcp_all_users"
    [path] = PathFinder(graph).find_all_paths()
    assert chain(path) == ["allUsers", ADMIN]
    assert path.severity is Severity.CRITICAL


def test_group_node_type() -> None:
    graph = build({"project_iam_policy": {"bindings": [
        {"role": "roles/viewer", "members": ["group:devs@x", "domain:x.com"]},
    ]}})
    assert graph.nodes["group:devs@x"]["node"].node_type == "gcp_group"
    assert graph.nodes["domain:x.com"]["node"].node_type == "gcp_domain"


def test_editor_is_not_already_admin() -> None:
    graph = build({"project_iam_policy": {"bindings": [
        {"role": "roles/editor", "members": ["user:ed@x"]},
    ]}})
    assert not graph.has_edge("user:ed@x", ADMIN)
    assert PathFinder(graph).find_all_paths() == []


def test_owner_also_impersonable_keeps_already_admin_only() -> None:
    # Un owner con tokenCreator sobre otra SA no recibe aristas de técnica
    graph = build({
        "project_iam_policy": {"bindings": [{"role": "roles/owner", "members": ["user:root@x"]}]},
        "service_accounts": [{"email": "s@p.iam.gserviceaccount.com", "iam_policy": {"bindings": [
            {"role": "roles/iam.serviceAccountTokenCreator", "members": ["user:root@x"]}]}}],
    })
    assert list(graph.successors("user:root@x")) == [ADMIN]
    assert filter_already_admin(PathFinder(graph).find_all_paths(), graph) == []


def test_build_is_repeatable() -> None:
    snap = load_snapshot(FIXTURE)
    principals = GCPResolver(snap).resolve_all()
    builder = GCPAttackGraph()
    first = builder.build(snap, principals)
    second = builder.build(snap, principals)
    assert first.number_of_edges() == second.number_of_edges() == 4
    assert builder.graph is second
