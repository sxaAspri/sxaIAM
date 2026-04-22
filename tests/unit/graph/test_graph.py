"""
tests/unit/graph/test_graph.py

Tests unitarios del módulo sxaiam.graph.

Cobertura:
  - nodes.py     : creación correcta de cada tipo de nodo, AdminNode singleton,
                   hash/eq, NODE_TYPES registry
  - builder.py   : pasada 1 (nodos), pasada 2 (aristas de técnicas y trust),
                   aristas con evidencia completa
  - pathfinder.py: BFS encuentra rutas, cutoff respetado, ordenación por
                   severidad, find_paths_from, caso sin rutas

Todos los tests usan fixtures mínimas construidas a mano — sin moto,
sin credenciales AWS reales, sin llamadas de red.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import networkx as nx
import pytest

from sxaiam.graph.nodes import (
    AdminNode,
    GroupNode,
    IAMNode,
    NODE_TYPE_ADMIN,
    NODE_TYPE_GROUP,
    NODE_TYPE_POLICY,
    NODE_TYPE_ROLE,
    NODE_TYPE_USER,
    NODE_TYPES,
    PolicyNode,
    RoleNode,
    UserNode,
)
from sxaiam.graph.builder import AttackGraph
from sxaiam.graph.pathfinder import PathFinder, DEFAULT_CUTOFF


# ===========================================================================
# Helpers / fixtures
# ===========================================================================

def _make_snapshot(
    users: list | None = None,
    roles: list | None = None,
    groups: list | None = None,
) -> MagicMock:
    """IAMSnapshot mínimo para tests."""
    snap = MagicMock()
    snap.users  = users  or []
    snap.roles  = roles  or []
    snap.groups = groups or []
    return snap


def _make_user(arn: str, name: str) -> MagicMock:
    u = MagicMock()
    u.arn       = arn
    u.user_name = name
    return u


def _make_role(
    arn: str,
    name: str,
    trust_principals: list[str] | None = None,
) -> MagicMock:
    """
    Crea un IAMRole mock.
    trust_principals: lista de ARNs que pueden asumir este rol.
    """
    role = MagicMock()
    role.arn       = arn
    role.role_name = name

    if trust_principals:
        stmt = MagicMock()
        stmt.effect    = "Allow"
        stmt.principal = {"AWS": trust_principals}

        doc = MagicMock()
        doc.statements = [stmt]

        role.assume_role_policy_document = doc
    else:
        role.assume_role_policy_document = None

    return role


def _make_group(arn: str, name: str) -> MagicMock:
    g = MagicMock()
    g.arn        = arn
    g.group_name = name
    return g


def _make_resolved(
    arn: str,
    permissions: list[tuple[str, str]] | None = None,
) -> MagicMock:
    """
    ResolvedIdentity mock.
    permissions: lista de (action, resource).
    """
    resolved = MagicMock()
    resolved.identity_arn = arn

    perms = []
    for action, resource in (permissions or []):
        ep = MagicMock()
        ep.action      = action
        ep.resource    = resource
        ep.source_type = "inline"
        ep.source_name = "test-policy"
        ep.source_arn  = f"{arn}/policy/test"
        perms.append(ep)

    resolved.permissions = perms
    return resolved


# ===========================================================================
# SECCIÓN 1 — nodes.py
# ===========================================================================

class TestNodeTypes:
    """Creación y propiedades básicas de cada tipo de nodo."""

    def test_user_node_type(self):
        node = UserNode(node_id="arn:aws:iam::123:user/alice", label="alice")
        assert node.node_type == NODE_TYPE_USER

    def test_role_node_type(self):
        node = RoleNode(node_id="arn:aws:iam::123:role/dev", label="dev")
        assert node.node_type == NODE_TYPE_ROLE

    def test_group_node_type(self):
        node = GroupNode(node_id="arn:aws:iam::123:group/devs", label="devs")
        assert node.node_type == NODE_TYPE_GROUP

    def test_policy_node_type(self):
        node = PolicyNode(
            node_id="arn:aws:iam::aws:policy/AdministratorAccess",
            label="AdministratorAccess",
        )
        assert node.node_type == NODE_TYPE_POLICY

    def test_admin_node_singleton_id(self):
        node = AdminNode()
        assert node.node_id   == "sxaiam::admin"
        assert node.node_type == NODE_TYPE_ADMIN
        assert node.label     == "AdministratorAccess"

    def test_admin_node_two_instances_equal(self):
        """Dos instancias de AdminNode deben ser iguales (mismo node_id)."""
        a = AdminNode()
        b = AdminNode()
        assert a == b
        assert hash(a) == hash(b)

    def test_role_node_has_trust_policy_default_false(self):
        node = RoleNode(node_id="arn:aws:iam::123:role/dev", label="dev")
        assert node.has_trust_policy is False

    def test_role_node_has_trust_policy_true(self):
        node = RoleNode(
            node_id="arn:aws:iam::123:role/dev",
            label="dev",
            has_trust_policy=True,
        )
        assert node.has_trust_policy is True

    def test_node_hash_equality(self):
        a = UserNode(node_id="arn:aws:iam::123:user/alice", label="alice")
        b = UserNode(node_id="arn:aws:iam::123:user/alice", label="alice")
        assert a == b
        assert hash(a) == hash(b)

    def test_node_inequality_different_arn(self):
        a = UserNode(node_id="arn:aws:iam::123:user/alice", label="alice")
        b = UserNode(node_id="arn:aws:iam::123:user/bob",   label="bob")
        assert a != b

    def test_node_types_registry_contains_all(self):
        assert NODE_TYPE_USER   in NODE_TYPES
        assert NODE_TYPE_ROLE   in NODE_TYPES
        assert NODE_TYPE_GROUP  in NODE_TYPES
        assert NODE_TYPE_POLICY in NODE_TYPES
        assert NODE_TYPE_ADMIN  in NODE_TYPES

    def test_node_types_registry_maps_to_correct_class(self):
        assert NODE_TYPES[NODE_TYPE_USER]   is UserNode
        assert NODE_TYPES[NODE_TYPE_ROLE]   is RoleNode
        assert NODE_TYPES[NODE_TYPE_GROUP]  is GroupNode
        assert NODE_TYPES[NODE_TYPE_POLICY] is PolicyNode
        assert NODE_TYPES[NODE_TYPE_ADMIN]  is AdminNode


# ===========================================================================
# SECCIÓN 2 — builder.py (pasada 1: nodos)
# ===========================================================================

class TestAttackGraphNodes:
    """Verifica que la pasada 1 del builder crea todos los nodos correctamente."""

    def _build_empty(self) -> nx.DiGraph:
        return AttackGraph().build(_make_snapshot(), [])

    def test_admin_node_always_present(self):
        G = self._build_empty()
        assert "sxaiam::admin" in G.nodes

    def test_admin_node_has_correct_type(self):
        G = self._build_empty()
        node = G.nodes["sxaiam::admin"]["node"]
        assert node.node_type == NODE_TYPE_ADMIN

    def test_user_nodes_created(self):
        user    = _make_user("arn:aws:iam::123:user/alice", "alice")
        snap    = _make_snapshot(users=[user])
        G       = AttackGraph().build(snap, [])
        assert user.arn in G.nodes

    def test_user_node_has_correct_type(self):
        user = _make_user("arn:aws:iam::123:user/alice", "alice")
        snap = _make_snapshot(users=[user])
        G    = AttackGraph().build(snap, [])
        node = G.nodes[user.arn]["node"]
        assert node.node_type == NODE_TYPE_USER
        assert node.label     == "alice"

    def test_role_nodes_created(self):
        role = _make_role("arn:aws:iam::123:role/dev", "dev")
        snap = _make_snapshot(roles=[role])
        G    = AttackGraph().build(snap, [])
        assert role.arn in G.nodes

    def test_role_node_has_correct_type(self):
        role = _make_role("arn:aws:iam::123:role/dev", "dev")
        snap = _make_snapshot(roles=[role])
        G    = AttackGraph().build(snap, [])
        node = G.nodes[role.arn]["node"]
        assert node.node_type == NODE_TYPE_ROLE

    def test_group_nodes_created(self):
        group = _make_group("arn:aws:iam::123:group/devs", "devs")
        snap  = _make_snapshot(groups=[group])
        G     = AttackGraph().build(snap, [])
        assert group.arn in G.nodes

    def test_multiple_nodes_all_present(self):
        user  = _make_user("arn:aws:iam::123:user/alice", "alice")
        role  = _make_role("arn:aws:iam::123:role/dev", "dev")
        group = _make_group("arn:aws:iam::123:group/devs", "devs")
        snap  = _make_snapshot(users=[user], roles=[role], groups=[group])
        G     = AttackGraph().build(snap, [])

        # AdminNode + user + role + group = 4 nodos
        assert G.number_of_nodes() == 4

    def test_empty_snapshot_only_admin_node(self):
        G = self._build_empty()
        assert G.number_of_nodes() == 1


# ===========================================================================
# SECCIÓN 3 — builder.py (pasada 2: aristas de técnicas)
# ===========================================================================

class TestAttackGraphEdges:
    """Verifica que la pasada 2 genera aristas con evidencia correcta."""

    def _build_with_technique_match(
        self,
        user_arn: str,
        technique_name: str,
        severity: str,
    ) -> nx.DiGraph:
        """
        Construye un grafo con una técnica que detecta escalación.
        Mockea ALL_TECHNIQUES para devolver un match controlado.
        """
        user = _make_user(user_arn, "alice")
        snap = _make_snapshot(users=[user])

        ep = MagicMock()
        ep.action      = "iam:CreatePolicyVersion"
        ep.resource    = "*"
        ep.source_type = "inline"
        ep.source_name = "test-policy"
        ep.source_arn  = f"{user_arn}/policy/test"

        match = MagicMock()
        match.technique_name = technique_name
        match.severity       = severity
        match.evidence       = [ep]
        match.attack_steps   = ["Step 1: do the thing"]
        match.target_arn     = None   # → AdminNode

        technique_instance = MagicMock()
        technique_instance.check.return_value = match

        technique_cls = MagicMock(return_value=technique_instance)

        resolved = _make_resolved(user_arn)

        with patch("sxaiam.graph.builder.ALL_TECHNIQUES", [technique_cls]):
            G = AttackGraph().build(snap, [resolved])

        return G

    def test_edge_created_to_admin_node(self):
        user_arn = "arn:aws:iam::123:user/alice"
        G = self._build_with_technique_match(
            user_arn, "CreatePolicyVersion", "CRITICAL"
        )
        admin_id = "sxaiam::admin"
        assert G.has_edge(user_arn, admin_id)

    def test_edge_has_technique_name(self):
        user_arn = "arn:aws:iam::123:user/alice"
        G = self._build_with_technique_match(
            user_arn, "CreatePolicyVersion", "CRITICAL"
        )
        edge = G.edges[user_arn, "sxaiam::admin"]
        assert edge["technique"] == "CreatePolicyVersion"

    def test_edge_has_severity(self):
        user_arn = "arn:aws:iam::123:user/alice"
        G = self._build_with_technique_match(
            user_arn, "CreatePolicyVersion", "CRITICAL"
        )
        edge = G.edges[user_arn, "sxaiam::admin"]
        assert edge["severity"] == "CRITICAL"

    def test_edge_has_evidence(self):
        user_arn = "arn:aws:iam::123:user/alice"
        G = self._build_with_technique_match(
            user_arn, "CreatePolicyVersion", "CRITICAL"
        )
        edge = G.edges[user_arn, "sxaiam::admin"]
        assert len(edge["evidence"]) == 1
        assert edge["evidence"][0]["action"] == "iam:CreatePolicyVersion"

    def test_edge_has_attack_steps(self):
        user_arn = "arn:aws:iam::123:user/alice"
        G = self._build_with_technique_match(
            user_arn, "CreatePolicyVersion", "CRITICAL"
        )
        edge = G.edges[user_arn, "sxaiam::admin"]
        assert "Step 1: do the thing" in edge["attack_steps"]

    def test_no_edge_when_technique_returns_none(self):
        user_arn = "arn:aws:iam::123:user/alice"
        user     = _make_user(user_arn, "alice")
        snap     = _make_snapshot(users=[user])
        resolved = _make_resolved(user_arn)

        technique_instance = MagicMock()
        technique_instance.check.return_value = None
        technique_cls = MagicMock(return_value=technique_instance)

        with patch("sxaiam.graph.builder.ALL_TECHNIQUES", [technique_cls]):
            G = AttackGraph().build(snap, [resolved])

        assert not G.has_edge(user_arn, "sxaiam::admin")

    def test_multiple_techniques_multiple_edges(self):
        """Si dos técnicas hacen match, solo se guarda una arista (la última)."""
        user_arn = "arn:aws:iam::123:user/alice"
        user     = _make_user(user_arn, "alice")
        snap     = _make_snapshot(users=[user])
        resolved = _make_resolved(user_arn)

        def _make_match(name: str) -> MagicMock:
            ep = MagicMock()
            ep.action = f"iam:{name}"
            ep.resource = "*"
            ep.source_type = "inline"
            ep.source_name = "test"
            ep.source_arn  = "test"

            m = MagicMock()
            m.technique_name = name
            m.severity       = "CRITICAL"
            m.evidence       = [ep]
            m.attack_steps   = []
            m.target_arn     = None
            return m

        t1 = MagicMock(return_value=MagicMock(check=MagicMock(
            return_value=_make_match("CreatePolicyVersion"))))
        t2 = MagicMock(return_value=MagicMock(check=MagicMock(
            return_value=_make_match("AttachUserPolicy"))))

        with patch("sxaiam.graph.builder.ALL_TECHNIQUES", [t1, t2]):
            G = AttackGraph().build(snap, [resolved])

        # networkx sobreescribe aristas paralelas — la última gana
        assert G.has_edge(user_arn, "sxaiam::admin")


# ===========================================================================
# SECCIÓN 4 — builder.py (pasada 2: aristas de trust policy)
# ===========================================================================

class TestTrustPolicyEdges:
    """Verifica que las trust policies generan aristas correctas."""

    def test_trust_edge_created(self):
        user_arn = "arn:aws:iam::123:user/alice"
        role_arn = "arn:aws:iam::123:role/admin-role"

        user = _make_user(user_arn, "alice")
        role = _make_role(role_arn, "admin-role", trust_principals=[user_arn])
        snap = _make_snapshot(users=[user], roles=[role])

        with patch("sxaiam.graph.builder.ALL_TECHNIQUES", []):
            G = AttackGraph().build(snap, [])

        assert G.has_edge(user_arn, role_arn)

    def test_trust_edge_technique_label(self):
        user_arn = "arn:aws:iam::123:user/alice"
        role_arn = "arn:aws:iam::123:role/admin-role"

        user = _make_user(user_arn, "alice")
        role = _make_role(role_arn, "admin-role", trust_principals=[user_arn])
        snap = _make_snapshot(users=[user], roles=[role])

        with patch("sxaiam.graph.builder.ALL_TECHNIQUES", []):
            G = AttackGraph().build(snap, [])

        edge = G.edges[user_arn, role_arn]
        assert edge["technique"] == "trust_policy"

    def test_no_self_loop_in_trust(self):
        role_arn = "arn:aws:iam::123:role/self-assuming"
        role = _make_role(role_arn, "self-assuming", trust_principals=[role_arn])
        snap = _make_snapshot(roles=[role])

        with patch("sxaiam.graph.builder.ALL_TECHNIQUES", []):
            G = AttackGraph().build(snap, [])

        assert not G.has_edge(role_arn, role_arn)

    def test_unknown_principal_ignored(self):
        """Un principal que no existe como nodo no debe crear aristas."""
        role_arn    = "arn:aws:iam::123:role/target"
        unknown_arn = "arn:aws:iam::999:user/external"

        role = _make_role(role_arn, "target", trust_principals=[unknown_arn])
        snap = _make_snapshot(roles=[role])

        with patch("sxaiam.graph.builder.ALL_TECHNIQUES", []):
            G = AttackGraph().build(snap, [])

        assert not G.has_edge(unknown_arn, role_arn)


# ===========================================================================
# SECCIÓN 5 — pathfinder.py
# ===========================================================================

def _build_linear_graph(
    nodes: list[tuple[str, str]],   # [(node_id, node_type), ...]
    edges: list[tuple[str, str, str, str]],  # [(src, dst, technique, severity)]
) -> nx.DiGraph:
    """
    Construye un DiGraph mínimo para tests del pathfinder.
    Siempre incluye AdminNode como último nodo si el tipo es 'admin'.
    """
    G = nx.DiGraph()

    for node_id, node_type in nodes:
        if node_type == NODE_TYPE_ADMIN:
            node_obj = AdminNode()
        elif node_type == NODE_TYPE_USER:
            node_obj = UserNode(node_id=node_id, label=node_id.split("/")[-1])
        elif node_type == NODE_TYPE_ROLE:
            node_obj = RoleNode(node_id=node_id, label=node_id.split("/")[-1])
        else:
            node_obj = IAMNode(node_id=node_id, node_type=node_type, label=node_id)

        G.add_node(node_id, node=node_obj)

    for src, dst, technique, severity in edges:
        G.add_edge(
            src, dst,
            technique=technique,
            severity=severity,
            evidence=[{"action": "iam:test", "resource": "*",
                        "source_type": "inline", "source_name": "p",
                        "source_arn": "p"}],
            attack_steps=["Step 1"],
            technique_match=None,
        )

    return G


ADMIN_ID = "sxaiam::admin"


class TestPathFinderBasic:
    """Tests básicos del PathFinder."""

    def test_finds_direct_path(self):
        """User → AdminNode en un salto."""
        user_arn = "arn:aws:iam::123:user/alice"
        G = _build_linear_graph(
            nodes=[(user_arn, NODE_TYPE_USER), (ADMIN_ID, NODE_TYPE_ADMIN)],
            edges=[(user_arn, ADMIN_ID, "CreatePolicyVersion", "CRITICAL")],
        )
        finder = PathFinder(G)
        paths  = finder.find_all_paths()

        assert len(paths) == 1
        assert paths[0].source_arn == user_arn

    def test_finds_two_hop_path(self):
        """User → Role → AdminNode en dos saltos."""
        user_arn = "arn:aws:iam::123:user/alice"
        role_arn = "arn:aws:iam::123:role/pivot"
        G = _build_linear_graph(
            nodes=[
                (user_arn, NODE_TYPE_USER),
                (role_arn, NODE_TYPE_ROLE),
                (ADMIN_ID, NODE_TYPE_ADMIN),
            ],
            edges=[
                (user_arn, role_arn, "trust_policy",  "INFO"),
                (role_arn, ADMIN_ID, "AttachUserPolicy", "CRITICAL"),
            ],
        )
        finder = PathFinder(G)
        paths  = finder.find_all_paths()

        assert len(paths) == 1
        assert len(paths[0].steps) == 2

    def test_no_paths_when_no_edges_to_admin(self):
        user_arn = "arn:aws:iam::123:user/alice"
        G = _build_linear_graph(
            nodes=[(user_arn, NODE_TYPE_USER), (ADMIN_ID, NODE_TYPE_ADMIN)],
            edges=[],
        )
        finder = PathFinder(G)
        paths  = finder.find_all_paths()
        assert paths == []

    def test_empty_graph_no_paths(self):
        G = nx.DiGraph()
        finder = PathFinder(G)
        paths  = finder.find_all_paths()
        assert paths == []

    def test_find_paths_from_specific_user(self):
        alice_arn = "arn:aws:iam::123:user/alice"
        bob_arn   = "arn:aws:iam::123:user/bob"
        G = _build_linear_graph(
            nodes=[
                (alice_arn, NODE_TYPE_USER),
                (bob_arn,   NODE_TYPE_USER),
                (ADMIN_ID,  NODE_TYPE_ADMIN),
            ],
            edges=[
                (alice_arn, ADMIN_ID, "CreatePolicyVersion", "CRITICAL"),
            ],
        )
        finder = PathFinder(G)

        alice_paths = finder.find_paths_from(alice_arn)
        bob_paths   = finder.find_paths_from(bob_arn)

        assert len(alice_paths) == 1
        assert len(bob_paths)   == 0

    def test_find_paths_from_nonexistent_node(self):
        G = _build_linear_graph(
            nodes=[(ADMIN_ID, NODE_TYPE_ADMIN)],
            edges=[],
        )
        finder = PathFinder(G)
        paths  = finder.find_paths_from("arn:aws:iam::123:user/ghost")
        assert paths == []


class TestPathFinderSeverityOrdering:
    """Verifica que las rutas se ordenan de mayor a menor severidad."""

    def test_critical_before_high(self):
        alice_arn = "arn:aws:iam::123:user/alice"
        bob_arn   = "arn:aws:iam::123:user/bob"
        G = _build_linear_graph(
            nodes=[
                (alice_arn, NODE_TYPE_USER),
                (bob_arn,   NODE_TYPE_USER),
                (ADMIN_ID,  NODE_TYPE_ADMIN),
            ],
            edges=[
                (bob_arn,   ADMIN_ID, "PassRoleLambda",       "HIGH"),
                (alice_arn, ADMIN_ID, "CreatePolicyVersion",  "CRITICAL"),
            ],
        )
        finder = PathFinder(G)
        paths  = finder.find_all_paths()

        assert len(paths) == 2
        assert paths[0].total_severity == "CRITICAL"
        assert paths[1].total_severity == "HIGH"

    def test_total_severity_is_max_of_steps(self):
        """Ruta de 2 pasos: INFO + CRITICAL → total CRITICAL."""
        user_arn = "arn:aws:iam::123:user/alice"
        role_arn = "arn:aws:iam::123:role/pivot"
        G = _build_linear_graph(
            nodes=[
                (user_arn, NODE_TYPE_USER),
                (role_arn, NODE_TYPE_ROLE),
                (ADMIN_ID, NODE_TYPE_ADMIN),
            ],
            edges=[
                (user_arn, role_arn, "trust_policy",        "INFO"),
                (role_arn, ADMIN_ID, "CreatePolicyVersion", "CRITICAL"),
            ],
        )
        finder = PathFinder(G)
        paths  = finder.find_all_paths()

        assert len(paths) == 1
        assert paths[0].total_severity == "CRITICAL"


class TestPathFinderCutoff:
    """Verifica que el cutoff limita la profundidad del BFS."""

    def test_cutoff_blocks_long_paths(self):
        """
        Cadena de 6 nodos: user → r1 → r2 → r3 → r4 → admin (5 saltos).
        Con cutoff=4 no debe encontrar la ruta.
        Con cutoff=5 sí debe encontrarla.
        """
        user_arn = "arn:aws:iam::123:user/alice"
        roles    = [f"arn:aws:iam::123:role/r{i}" for i in range(1, 5)]

        all_nodes = (
            [(user_arn, NODE_TYPE_USER)]
            + [(r, NODE_TYPE_ROLE) for r in roles]
            + [(ADMIN_ID, NODE_TYPE_ADMIN)]
        )

        chain = [user_arn] + roles + [ADMIN_ID]
        all_edges = [
            (chain[i], chain[i + 1], "trust_policy", "INFO")
            for i in range(len(chain) - 1)
        ]

        G = _build_linear_graph(all_nodes, all_edges)

        finder_strict = PathFinder(G, cutoff=4)
        finder_normal = PathFinder(G, cutoff=5)

        assert finder_strict.find_all_paths() == []
        assert len(finder_normal.find_all_paths()) == 1

    def test_default_cutoff_value(self):
        assert DEFAULT_CUTOFF == 5


class TestPathFinderSteps:
    """Verifica la estructura interna de los PathStep."""

    def test_step_has_technique_name(self):
        user_arn = "arn:aws:iam::123:user/alice"
        G = _build_linear_graph(
            nodes=[(user_arn, NODE_TYPE_USER), (ADMIN_ID, NODE_TYPE_ADMIN)],
            edges=[(user_arn, ADMIN_ID, "CreatePolicyVersion", "CRITICAL")],
        )
        finder = PathFinder(G)
        path   = finder.find_all_paths()[0]
        assert path.steps[0].technique_name == "CreatePolicyVersion"

    def test_step_has_from_and_to_arn(self):
        user_arn = "arn:aws:iam::123:user/alice"
        G = _build_linear_graph(
            nodes=[(user_arn, NODE_TYPE_USER), (ADMIN_ID, NODE_TYPE_ADMIN)],
            edges=[(user_arn, ADMIN_ID, "CreatePolicyVersion", "CRITICAL")],
        )
        finder = PathFinder(G)
        step   = finder.find_all_paths()[0].steps[0]
        assert step.from_arn == user_arn
        assert step.to_arn   == ADMIN_ID

    def test_step_has_evidence(self):
        user_arn = "arn:aws:iam::123:user/alice"
        G = _build_linear_graph(
            nodes=[(user_arn, NODE_TYPE_USER), (ADMIN_ID, NODE_TYPE_ADMIN)],
            edges=[(user_arn, ADMIN_ID, "CreatePolicyVersion", "CRITICAL")],
        )
        finder = PathFinder(G)
        step   = finder.find_all_paths()[0].steps[0]
        assert len(step.evidence) > 0
        assert step.evidence[0]["action"] == "iam:test"
