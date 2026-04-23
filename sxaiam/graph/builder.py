"""
sxaiam/graph/builder.py

Motor de construcción del grafo de ataque IAM.

Regla de arquitectura #2: el builder es completamente independiente
del policy resolver y de las técnicas de escalación. Recibe sus
outputs como parámetros — nunca los instancia internamente.

Regla de arquitectura #3: el builder no decide qué es escalación.
Las técnicas (findings/techniques.py) generan los TechniqueMatch;
el builder solo convierte esos matches en aristas del grafo con
su evidencia correspondiente.

Flujo de build() — dos pasadas:
  Pasada 1 — Nodos
    • Un UserNode  por cada IAMUser  en el snapshot
    • Un RoleNode  por cada IAMRole  en el snapshot
    • Un GroupNode por cada IAMGroup en el snapshot
    • Un AdminNode singleton (destino virtual del BFS)

  Pasada 2 — Aristas
    • Para cada ResolvedIdentity, correr ALL_TECHNIQUES
    • Cada TechniqueMatch genera una arista con evidencia
    • Las trust policies generan aristas especiales USER→ROLE / ROLE→ROLE

Estructura de una arista (atributos del DiGraph):
  {
    "technique":   str,           # nombre de la técnica
    "severity":    str,           # CRITICAL / HIGH / MEDIUM
    "evidence":    list[dict],    # permisos que justifican la arista
    "attack_steps": list[str],    # pasos del ataque
    "technique_match": TechniqueMatch  # objeto completo para serialización
  }
"""

from __future__ import annotations

import logging
from typing import Optional

import networkx as nx

from sxaiam.findings.technique_base import TechniqueMatch
from sxaiam.findings.techniques import ALL_TECHNIQUES
from sxaiam.graph.nodes import (
    AdminNode,
    GroupNode,
    IAMNode,
    NODE_TYPE_ADMIN,
    RoleNode,
    UserNode,
)
from sxaiam.ingestion.models import IAMSnapshot
from sxaiam.resolver.models import ResolvedIdentity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

# Acciones que por sí solas equivalen a AdministratorAccess
_ADMIN_ACTIONS = frozenset({
    "*",
    "iam:*",
})

# Política administrada de AWS que equivale a admin
_ADMIN_POLICY_ARNS = frozenset({
    "arn:aws:iam::aws:policy/AdministratorAccess",
})


# ---------------------------------------------------------------------------
# AttackGraph
# ---------------------------------------------------------------------------

class AttackGraph:
    """
    Grafo dirigido de rutas de ataque IAM.

    Uso básico:
        snapshot  = ingestion_client.get_snapshot()
        resolved  = PolicyResolver(snapshot).resolve_all()
        graph     = AttackGraph()
        G         = graph.build(snapshot, resolved)
        # G es un networkx.DiGraph listo para PathFinder

    Atributos del grafo resultante:
        G.nodes[node_id]["node"]  → objeto IAMNode
        G.edges[src, dst]         → dict con technique, severity, evidence, ...
    """

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()
        self._nodes: dict[str, IAMNode] = {}   # node_id → IAMNode
        self._admin_node: AdminNode = AdminNode()

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def build(
        self,
        snapshot: IAMSnapshot,
        resolved_identities: list[ResolvedIdentity],
    ) -> nx.DiGraph:
        """
        Construye y devuelve el DiGraph completo en dos pasadas.

        Args:
            snapshot:             IAMSnapshot con usuarios, roles y grupos.
            resolved_identities:  Output de PolicyResolver.resolve_all().

        Returns:
            networkx.DiGraph donde cada nodo tiene el atributo "node"
            y cada arista tiene technique, severity y evidence.
        """
        logger.info("AttackGraph.build() — iniciando construcción del grafo")

        self._graph = nx.DiGraph()
        self._nodes = {}

        # ── Pasada 1: nodos ──────────────────────────────────────────
        self._build_nodes(snapshot)

        # ── Pasada 2: aristas ────────────────────────────────────────
        self._build_edges(snapshot, resolved_identities)

        logger.info(
            "Grafo construido: %d nodos, %d aristas",
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
        )
        return self._graph

    @property
    def graph(self) -> nx.DiGraph:
        """Acceso directo al DiGraph después de build()."""
        return self._graph

    # ------------------------------------------------------------------
    # Pasada 1 — Nodos
    # ------------------------------------------------------------------

    def _build_nodes(self, snapshot: IAMSnapshot) -> None:
        """Crea todos los nodos y los añade al grafo."""

        # AdminNode — singleton virtual, siempre presente
        self._add_node(self._admin_node)
        logger.debug("AdminNode añadido: %s", self._admin_node.node_id)

        # Usuarios
        for user in snapshot.users:
            node = UserNode(
                node_id=user.arn,
                label=user.user_name,
                account_id=_extract_account_id(user.arn),
            )
            self._add_node(node)

        logger.debug("%d UserNodes añadidos", len(snapshot.users))

        # Roles
        for role in snapshot.roles:
            has_trust = bool(
                role.assume_role_policy_document
                and role.assume_role_policy_document.statements
            )
            node = RoleNode(
                node_id=role.arn,
                label=role.role_name,
                account_id=_extract_account_id(role.arn),
                has_trust_policy=has_trust,
            )
            self._add_node(node)

        logger.debug("%d RoleNodes añadidos", len(snapshot.roles))

        # Grupos
        for group in snapshot.groups:
            node = GroupNode(
                node_id=group.arn,
                label=group.group_name,
                account_id=_extract_account_id(group.arn),
            )
            self._add_node(node)

        logger.debug("%d GroupNodes añadidos", len(snapshot.groups))

    def _add_node(self, node: IAMNode) -> None:
        """Registra un nodo en el grafo y en el índice interno."""
        self._nodes[node.node_id] = node
        self._graph.add_node(node.node_id, node=node)

    # ------------------------------------------------------------------
    # Pasada 2 — Aristas
    # ------------------------------------------------------------------

    def _build_edges(
        self,
        snapshot: IAMSnapshot,
        resolved_identities: list[ResolvedIdentity],
    ) -> None:
        """
        Genera todas las aristas del grafo a partir de:
          1. TechniqueMatches producidos por ALL_TECHNIQUES
          2. Trust policies del snapshot (aristas de AssumeRole entre nodos)
        """
        # Índice rápido ARN → ResolvedIdentity
        resolved_by_arn: dict[str, ResolvedIdentity] = {
            ri.identity_arn: ri for ri in resolved_identities
        }

        # 2a — Aristas de técnicas de escalación
        self._build_technique_edges(resolved_by_arn, snapshot)

        # 2b — Aristas de trust policies (AssumeRole entre identidades)
        self._build_trust_edges(snapshot, resolved_by_arn)

    def _build_technique_edges(
        self,
        resolved_by_arn: dict[str, ResolvedIdentity],
        snapshot: IAMSnapshot,
    ) -> None:
        """
        Para cada identidad resuelta, corre ALL_TECHNIQUES y convierte
        cada TechniqueMatch en una arista hacia el AdminNode o hacia
        el nodo objetivo de la técnica.
        """
        admin_id = self._admin_node.node_id

        for identity_arn, resolved in resolved_by_arn.items():

            if identity_arn not in self._nodes:
                logger.debug(
                    "Identidad %s no tiene nodo en el grafo — saltando",
                    identity_arn,
                )
                continue

            for technique_cls in ALL_TECHNIQUES:
                technique = technique_cls()
                matches: list[TechniqueMatch] = technique.check(resolved, snapshot) or []

                for match in matches:
                    target_id = _resolve_target(match, self._nodes, admin_id)

                    evidence_dicts = [
                        {
                            "action":      ep,
                            "resource":    "*",
                            "source_type": "policy",
                            "source_name": match.technique_name,
                            "source_arn":  match.origin_arn,
                        }
                        for ep in match.evidence
                    ]

                    self._graph.add_edge(
                        identity_arn,
                        target_id,
                        technique=match.technique_id,
                        severity=match.severity.value,
                        evidence=evidence_dicts,
                        attack_steps=match.attack_steps,
                        technique_match=match,
                    )

                    logger.debug(
                        "Arista añadida: %s → %s [%s / %s]",
                        identity_arn,
                        target_id,
                        match.technique_id,
                        match.severity.value,
                    )

    def _build_trust_edges(
        self,
        snapshot: IAMSnapshot,
        resolved_by_arn: dict[str, ResolvedIdentity],
    ) -> None:
        """
        Genera aristas de tipo 'AssumeRole' entre identidades basándose
        en las trust policies de los roles del snapshot.

        Si la identidad A tiene sts:AssumeRole sobre el rol B (según la
        trust policy de B), se añade la arista A → B con tipo 'trust_policy'.

        Nota: esta es la lógica simplificada de v0.1.0. La Fase 3C completa
        puede expandirla para manejar condiciones en trust policies,
        cross-account, etc.
        """
        for role in snapshot.roles:
            if not role.assume_role_policy_document:
                continue

            role_node_id = role.arn

            for stmt in role.assume_role_policy_document.statements:
                if stmt.effect != "Allow":
                    continue

                # Normalizar principals a lista
                principals = _normalize_principals(stmt.principal)

                for principal_arn in principals:
                    # Solo nos interesan principals que existen como nodos
                    if principal_arn not in self._nodes:
                        continue

                    # No añadir self-loops
                    if principal_arn == role_node_id:
                        continue

                    # Solo añadir si no existe ya una arista de técnica
                    # (la técnica AssumeRoleChain tiene prioridad)
                    if not self._graph.has_edge(principal_arn, role_node_id):
                        self._graph.add_edge(
                            principal_arn,
                            role_node_id,
                            technique="trust_policy",
                            severity="INFO",
                            evidence=[{
                                "action":      "sts:AssumeRole",
                                "resource":    role.arn,
                                "source_type": "trust_policy",
                                "source_name": role.role_name,
                                "source_arn":  role.arn,
                            }],
                            attack_steps=[
                                f"aws sts assume-role --role-arn {role.arn} "
                                f"--role-session-name attack"
                            ],
                            technique_match=None,
                        )

                        logger.debug(
                            "Trust edge: %s → %s",
                            principal_arn,
                            role_node_id,
                        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_account_id(arn: str) -> Optional[str]:
    """
    Extrae el account ID de un ARN de AWS.
    arn:aws:iam::123456789012:user/alice → "123456789012"
    Devuelve None si el ARN no tiene el formato esperado.
    """
    try:
        parts = arn.split(":")
        account = parts[4]
        return account if account else None
    except IndexError:
        return None


def _resolve_target(
    match: TechniqueMatch,
    nodes: dict[str, IAMNode],
    admin_id: str,
) -> str:
    """
    Determina el node_id destino de una arista a partir de un TechniqueMatch.

    Si el match tiene target_arn y ese ARN existe como nodo, la arista
    apunta a ese nodo. En cualquier otro caso, apunta al AdminNode.
    """
    target_arn: Optional[str] = getattr(match, "target_arn", None)
    if target_arn and target_arn in nodes:
        return target_arn
    return admin_id


def _normalize_principals(principal: object) -> list[str]:
    """
    Normaliza el campo Principal de una trust policy statement a lista de ARNs.

    Principal puede ser:
      - "*"                          → lista vacía (wildcard, ignorar en v0.1.0)
      - "arn:aws:iam::...:root"      → ["arn:aws:iam::...:root"]
      - {"AWS": "arn:..."}           → ["arn:..."]
      - {"AWS": ["arn:...", "arn:"]} → ["arn:...", "arn:..."]
      - {"Service": "lambda..."}     → lista vacía (servicios, ignorar)
      - {"Federated": "..."}         → lista vacía (federación, ignorar)
    """
    if principal is None:
        return []

    if isinstance(principal, str):
        # Wildcard — ignorar en v0.1.0
        return []

    if not isinstance(principal, dict):
        return []

    aws_principals = principal.get("AWS")
    if not aws_principals:
        return []

    if isinstance(aws_principals, str):
        return [aws_principals]

    if isinstance(aws_principals, list):
        return [p for p in aws_principals if isinstance(p, str)]

    return []
