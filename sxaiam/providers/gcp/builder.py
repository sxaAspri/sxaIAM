"""
sxaiam.providers.gcp.builder
============================
Construye el grafo de ataque GCP: el mismo ``nx.DiGraph`` que produce el
builder AWS, para que ``PathFinder`` y los exportadores funcionen sin cambios.

    G.nodes[node_id]["node"]  -> IAMNode (subclases GCP + AdminNode)
    G.edges[src, dst]         -> technique, severity, evidence (list[str]),
                                 attack_steps, technique_match

Aristas:
    - ``already-admin`` (INFO, sin technique_match): miembro con ``roles/owner``
      sin condición → AdminNode. Esos principales NO se evalúan contra técnicas:
      ``owner`` tiene ``setIamPolicy`` y la técnica 1 crearía una arista CRITICAL
      que le ganaría a la INFO, volviendo CRITICAL toda ruta que pase por ellos.
    - Técnicas de ``GCPTechniqueRegistry``, conservando la de mayor severidad
      cuando dos técnicas unen el mismo par de nodos.

``PathFinder.find_all_paths()`` también devuelve la ruta trivial
``owner → admin``; ``filter_already_admin()`` la descarta.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import networkx as nx

from sxaiam.findings.escalation_path import EscalationPath
from sxaiam.graph.nodes import AdminNode, IAMNode
from sxaiam.providers.gcp.models import GCPSnapshot
from sxaiam.providers.gcp.resolver import (
    GCPResolvedPrincipal,
    MemberKind,
    is_admin_member,
    project_resource,
)
from sxaiam.providers.gcp.roles import ADMIN_ROLE
from sxaiam.providers.gcp.techniques import GCPTechniqueRegistry

logger = logging.getLogger(__name__)

ALREADY_ADMIN = "already-admin"

NODE_TYPE_GCP_USER = "gcp_user"
NODE_TYPE_GCP_SERVICE_ACCOUNT = "gcp_service_account"

_NODE_TYPE_BY_KIND = {
    MemberKind.GROUP: "gcp_group",
    MemberKind.DOMAIN: "gcp_domain",
    MemberKind.ALL_USERS: "gcp_all_users",
    MemberKind.ALL_AUTHENTICATED_USERS: "gcp_all_authenticated_users",
}

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


# ---------------------------------------------------------------------------
# Nodos GCP (subclases de IAMNode; node_id = miembro IAM, account_id = proyecto)
# ---------------------------------------------------------------------------

@dataclass(unsafe_hash=True)
class GCPUserNode(IAMNode):
    node_type: str = field(default=NODE_TYPE_GCP_USER, init=False)


@dataclass(unsafe_hash=True)
class GCPServiceAccountNode(IAMNode):
    node_type: str = field(default=NODE_TYPE_GCP_SERVICE_ACCOUNT, init=False)


@dataclass(unsafe_hash=True)
class GCPPrincipalNode(IAMNode):
    """Grupo, dominio, allUsers o allAuthenticatedUsers (node_type según el tipo)."""


def _make_node(principal: GCPResolvedPrincipal, project_id: str) -> IAMNode:
    if principal.kind is MemberKind.USER:
        return GCPUserNode(node_id=principal.member, label=principal.name, account_id=project_id)
    if principal.kind is MemberKind.SERVICE_ACCOUNT:
        return GCPServiceAccountNode(
            node_id=principal.member, label=principal.name, account_id=project_id,
        )
    return GCPPrincipalNode(
        node_id=principal.member,
        node_type=_NODE_TYPE_BY_KIND[principal.kind],
        label=principal.name,
        account_id=project_id,
    )


# ---------------------------------------------------------------------------
# GCPAttackGraph
# ---------------------------------------------------------------------------

class GCPAttackGraph:
    """
    Uso::

        snapshot = load_snapshot("proyecto.json")
        principals = GCPResolver(snapshot).resolve_all()
        G = GCPAttackGraph().build(snapshot, principals)
        paths = filter_already_admin(PathFinder(G).find_all_paths(), G)
    """

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()
        self._admin_node = AdminNode()

    @property
    def graph(self) -> nx.DiGraph:
        return self._graph

    def build(
        self,
        snapshot: GCPSnapshot,
        principals: dict[str, GCPResolvedPrincipal],
    ) -> nx.DiGraph:
        self._graph = nx.DiGraph()
        self._graph.add_node(self._admin_node.node_id, node=self._admin_node)
        for principal in principals.values():
            node = _make_node(principal, snapshot.project_id)
            self._graph.add_node(node.node_id, node=node)

        for member, principal in principals.items():
            if is_admin_member(member, snapshot):
                self._add_already_admin_edge(member, snapshot)
            else:
                self._add_technique_edges(principal, snapshot)

        logger.info(
            "GCPAttackGraph: %d nodos, %d aristas",
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
        )
        return self._graph

    # ------------------------------------------------------------------

    def _add_already_admin_edge(self, member: str, snapshot: GCPSnapshot) -> None:
        self._graph.add_edge(
            member,
            self._admin_node.node_id,
            technique=ALREADY_ADMIN,
            severity="INFO",
            evidence=[f"{member} holds {ADMIN_ROLE} on {project_resource(snapshot.project_id)}"],
            attack_steps=[],
            technique_match=None,
        )

    def _add_technique_edges(
        self,
        principal: GCPResolvedPrincipal,
        snapshot: GCPSnapshot,
    ) -> None:
        source = principal.member
        for technique in GCPTechniqueRegistry.all():
            for match in technique.check(principal, snapshot):
                target = match.target_arn
                if target not in self._graph:
                    # A diferencia de AWS (_resolve_target), no se redirige al
                    # AdminNode: eso inventaría una ruta a admin.
                    logger.warning(
                        "Objetivo %s de %s no existe en el grafo — arista descartada",
                        target, match.technique_id,
                    )
                    continue

                if self._graph.has_edge(source, target):
                    existing = self._graph.edges[source, target]["severity"]
                    if _SEVERITY_RANK[match.severity.value] <= _SEVERITY_RANK[existing]:
                        continue

                self._graph.add_edge(
                    source,
                    target,
                    technique=match.technique_id,
                    severity=match.severity.value,
                    evidence=list(match.evidence),
                    attack_steps=list(match.attack_steps),
                    technique_match=match,
                )


# ---------------------------------------------------------------------------
# Filtro de rutas
# ---------------------------------------------------------------------------

def is_already_admin_node(graph: nx.DiGraph, node_id: str) -> bool:
    """True si el nodo tiene la arista ``already-admin`` hacia el AdminNode."""
    admin_id = AdminNode().node_id
    return (
        graph.has_edge(node_id, admin_id)
        and graph.edges[node_id, admin_id].get("technique") == ALREADY_ADMIN
    )


def filter_already_admin(
    paths: list[EscalationPath],
    graph: nx.DiGraph,
) -> list[EscalationPath]:
    """
    Descarta las rutas cuyo **origen** ya es admin: no son escalamiento.
    Las rutas que solo **pasan** por un admin (bob → deployer → admin) se conservan.
    """
    return [p for p in paths if not is_already_admin_node(graph, p.steps[0].from_arn)]
