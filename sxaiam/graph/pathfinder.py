"""
sxaiam/graph/pathfinder.py

Motor de búsqueda de rutas de escalación de privilegios.

Recibe el DiGraph construido por AttackGraph.build() y encuentra
todas las rutas desde cualquier nodo de inicio hasta el AdminNode
usando BFS (Breadth-First Search).

Decisiones de diseño:
  - BFS en lugar de DFS: encuentra rutas más cortas primero, que en
    un contexto ofensivo son las más relevantes (menor superficie de
    exposición).
  - cutoff=5: límite de profundidad para evitar explosión combinatoria
    en cuentas grandes. Rutas de más de 5 saltos son poco realistas
    en un escenario de escalación real.
  - El pathfinder no conoce las técnicas ni el resolver — solo trabaja
    con el grafo y convierte las aristas en EscalationPath.
  - Una ruta con un solo salto directo (identidad → AdminNode) es
    válida y representa el caso más crítico.

Output:
  Lista de EscalationPath, cada uno con:
    - source_arn:   identidad de inicio
    - steps:        lista de PathStep con evidencia por arista
    - total_severity: severidad más alta en la ruta
"""

from __future__ import annotations

import logging
from typing import Optional

import networkx as nx

from sxaiam.findings.escalation_path import EscalationPath, PathStep
from sxaiam.graph.nodes import NODE_TYPE_ADMIN, IAMNode

logger = logging.getLogger(__name__)

# Límite de profundidad del BFS.
# Rutas de más de 5 saltos son teóricamente posibles pero prácticamente
# irrelevantes — y explosivas en cuentas con muchos roles.
DEFAULT_CUTOFF = 5

# Orden de severidad para calcular la severidad total de una ruta
_SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}


class PathFinder:
    """
    Encuentra todas las rutas de escalación de privilegios en el grafo.

    Uso básico:
        G       = attack_graph.build(snapshot, resolved)
        finder  = PathFinder(G)
        paths   = finder.find_all_paths()

        # Solo rutas desde una identidad específica
        paths   = finder.find_paths_from("arn:aws:iam::123:user/alice")
    """

    def __init__(self, graph: nx.DiGraph, cutoff: int = DEFAULT_CUTOFF) -> None:
        self._graph  = graph
        self._cutoff = cutoff
        self._admin_id = self._find_admin_node()

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def find_all_paths(self) -> list[EscalationPath]:
        """
        Encuentra todas las rutas de escalación hacia AdminNode
        desde todos los nodos del grafo.

        Excluye el AdminNode como punto de partida.

        Returns:
            Lista de EscalationPath ordenada por severidad descendente.
        """
        if self._admin_id is None:
            logger.warning("AdminNode no encontrado en el grafo — sin rutas")
            return []

        all_paths: list[EscalationPath] = []

        for node_id in self._graph.nodes:
            if node_id == self._admin_id:
                continue

            node_paths = self._bfs_from(node_id)
            all_paths.extend(node_paths)

        logger.info(
            "PathFinder: %d rutas de escalación encontradas", len(all_paths)
        )

        return _sort_by_severity(all_paths)

    def find_paths_from(self, source_arn: str) -> list[EscalationPath]:
        """
        Encuentra todas las rutas de escalación desde una identidad específica.

        Args:
            source_arn: ARN del nodo de inicio (usuario o rol).

        Returns:
            Lista de EscalationPath desde esa identidad, ordenada por severidad.
        """
        if self._admin_id is None:
            logger.warning("AdminNode no encontrado en el grafo — sin rutas")
            return []

        if source_arn not in self._graph:
            logger.debug("Nodo %s no existe en el grafo", source_arn)
            return []

        paths = self._bfs_from(source_arn)
        return _sort_by_severity(paths)

    def find_paths_to_admin(self) -> list[EscalationPath]:
        """
        Alias semántico de find_all_paths().
        Útil cuando se quiere ser explícito sobre el destino.
        """
        return self.find_all_paths()

    # ------------------------------------------------------------------
    # BFS interno
    # ------------------------------------------------------------------

    def _bfs_from(self, source_id: str) -> list[EscalationPath]:
        """
        Ejecuta BFS desde source_id hacia AdminNode con cutoff.

        Usa networkx.all_simple_paths que internamente hace BFS/DFS
        limitado. Filtramos solo las rutas que llegan al AdminNode.

        Returns:
            Lista de EscalationPath que llegan al AdminNode.
        """
        if self._admin_id is None:
            return []

        escalation_paths: list[EscalationPath] = []

        try:
            raw_paths = nx.all_simple_paths(
                self._graph,
                source=source_id,
                target=self._admin_id,
                cutoff=self._cutoff,
            )

            for node_sequence in raw_paths:
                path = self._sequence_to_escalation_path(node_sequence)
                if path is not None:
                    escalation_paths.append(path)

        except nx.NetworkXError as exc:
            logger.debug(
                "BFS error desde %s: %s", source_id, exc
            )

        return escalation_paths

    def _sequence_to_escalation_path(
        self,
        node_sequence: list[str],
    ) -> Optional[EscalationPath]:
        """
        Convierte una secuencia de node_ids en un EscalationPath.

        Cada par (node_sequence[i], node_sequence[i+1]) es una arista
        del grafo con sus atributos de técnica y evidencia.

        Returns:
            EscalationPath con todos los steps, o None si la secuencia
            tiene menos de 2 nodos (no es una ruta válida).
        """
        if len(node_sequence) < 2:
            return None

        source_arn = node_sequence[0]
        steps: list[PathStep] = []

        for i in range(len(node_sequence) - 1):
            src = node_sequence[i]
            dst = node_sequence[i + 1]

            edge_data = self._graph.edges[src, dst]

            # Nombre del nodo destino para el step
            dst_label = _get_node_label(self._graph, dst)

            step = PathStep(
                technique_name=edge_data.get("technique", "unknown"),
                severity=edge_data.get("severity", "INFO"),
                from_arn=src,
                to_arn=dst,
                to_label=dst_label,
                evidence=edge_data.get("evidence", []),
                attack_steps=edge_data.get("attack_steps", []),
            )
            steps.append(step)

        if not steps:
            return None

        total_severity = _compute_total_severity(steps)

        # Obtener el technique_match del primer step de técnica real
        # (no trust_policy) para metadata del EscalationPath
        primary_match = None
        for i in range(len(node_sequence) - 1):
            src = node_sequence[i]
            dst = node_sequence[i + 1]
            tm = self._graph.edges[src, dst].get("technique_match")
            if tm is not None:
                primary_match = tm
                break

        return EscalationPath(
            source_arn=source_arn,
            steps=steps,
            total_severity=total_severity,
            technique_match=primary_match,
        )

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------

    def _find_admin_node(self) -> Optional[str]:
        """
        Busca el AdminNode en el grafo por node_type.

        Returns:
            node_id del AdminNode o None si no existe.
        """
        for node_id, data in self._graph.nodes(data=True):
            node_obj: Optional[IAMNode] = data.get("node")
            if node_obj and node_obj.node_type == NODE_TYPE_ADMIN:
                return node_id

        logger.warning("AdminNode no encontrado en el grafo")
        return None


# ---------------------------------------------------------------------------
# Helpers de módulo
# ---------------------------------------------------------------------------

def _get_node_label(graph: nx.DiGraph, node_id: str) -> str:
    """Devuelve el label del nodo o el node_id si no tiene label."""
    data = graph.nodes.get(node_id, {})
    node_obj: Optional[IAMNode] = data.get("node")
    if node_obj:
        return node_obj.label
    return node_id


def _compute_total_severity(steps: list[PathStep]) -> str:
    """
    Devuelve la severidad más alta entre todos los steps de la ruta.
    Una ruta hereda la peor severidad de sus aristas.
    """
    if not steps:
        return "INFO"

    return max(
        steps,
        key=lambda s: _SEVERITY_ORDER.get(s.severity, 0),
    ).severity


def _sort_by_severity(paths: list[EscalationPath]) -> list[EscalationPath]:
    """Ordena rutas de mayor a menor severidad."""
    return sorted(
        paths,
        key=lambda p: _SEVERITY_ORDER.get(p.total_severity, 0),
        reverse=True,
    )
