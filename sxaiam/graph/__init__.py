"""
sxaiam/graph/__init__.py

Módulo de análisis de rutas de ataque IAM.

Exports públicos:
    AttackGraph  — construye el DiGraph desde un IAMSnapshot + ResolvedIdentities
    PathFinder   — encuentra rutas de escalación hacia AdminNode via BFS
    AdminNode    — nodo virtual singleton que representa AdministratorAccess
    UserNode     — nodo de usuario IAM
    RoleNode     — nodo de rol IAM
    GroupNode    — nodo de grupo IAM
    PolicyNode   — nodo de política IAM

Uso típico:
    from sxaiam.graph import AttackGraph, PathFinder

    graph   = AttackGraph()
    G       = graph.build(snapshot, resolved_identities)

    finder  = PathFinder(G)
    paths   = finder.find_all_paths()

    for path in paths:
        print(path.to_markdown())
"""

from sxaiam.graph.builder import AttackGraph
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
from sxaiam.graph.pathfinder import PathFinder

__all__ = [
    # Builder
    "AttackGraph",
    # PathFinder
    "PathFinder",
    # Nodos
    "IAMNode",
    "UserNode",
    "RoleNode",
    "GroupNode",
    "PolicyNode",
    "AdminNode",
    # Constantes de tipo
    "NODE_TYPE_USER",
    "NODE_TYPE_ROLE",
    "NODE_TYPE_GROUP",
    "NODE_TYPE_POLICY",
    "NODE_TYPE_ADMIN",
    "NODE_TYPES",
]
