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
    - origin_arn:     identidad de inicio
    - steps:          lista de PathStep con evidencia por arista
    - severity:       severidad más alta en la ruta (como Severity enum)
"""

from __future__ import annotations

import logging
import uuid

import networkx as nx

from sxaiam.findings.escalation_path import EscalationPath, PathStep
from sxaiam.findings.technique_base import Severity
from sxaiam.graph.nodes import NODE_TYPE_ADMIN, IAMNode

logger = logging.getLogger(__name__)

# Límite de profundidad del BFS.
DEFAULT_CUTOFF = 5

# Orden de severidad para calcular la severidad total de una ruta
_SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}

# Mapeo de string → Severity enum para construir EscalationPath
_STR_TO_SEVERITY: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
    "INFO":     Severity.INFO,
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
            all_paths.extend(self._bfs_from(node_id))

        logger.info("PathFinder: %d rutas encontradas", len(all_paths))
        return _sort_by_severity(all_paths)

    def find_paths_from(self, source_arn: str) -> list[EscalationPath]:
        """
        Encuentra todas las rutas desde una identidad específica.

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

        return _sort_by_severity(self._bfs_from(source_arn))

    def find_paths_to_admin(self) -> list[EscalationPath]:
        """Alias semántico de find_all_paths()."""
        return self.find_all_paths()

    # ------------------------------------------------------------------
    # BFS interno
    # ------------------------------------------------------------------

    def _bfs_from(self, source_id: str) -> list[EscalationPath]:
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
            logger.debug("BFS error desde %s: %s", source_id, exc)

        return escalation_paths

    def _sequence_to_escalation_path(
        self,
        node_sequence: list[str],
    ) -> EscalationPath | None:
        """
        Convierte una secuencia de node_ids en un EscalationPath.
        """
        if len(node_sequence) < 2:
            return None

        source_id    = node_sequence[0]
        source_label = _get_node_label(self._graph, source_id)
        steps: list[PathStep] = []

        for i, (src, dst) in enumerate(
            zip(node_sequence[:-1], node_sequence[1:]), start=1
        ):
            edge_data = self._graph.edges[src, dst]
            src_label = _get_node_label(self._graph, src)
            dst_label = _get_node_label(self._graph, dst)

            # El builder guarda evidencia como list[dict] — PathStep.evidence
            # es list[str], convertimos a strings legibles.
            evidence_strs = _evidence_to_strings(edge_data.get("evidence", []))

            step = PathStep(
                step_number=i,
                from_arn=src,
                from_name=src_label,
                to_arn=dst,
                to_name=dst_label,
                technique_id=edge_data.get("technique", "unknown"),
                technique_name=edge_data.get("technique", "unknown"),
                severity=edge_data.get("severity", "INFO"),
                evidence=evidence_strs,
                api_calls=edge_data.get("attack_steps", []),
            )
            steps.append(step)

        if not steps:
            return None

        # Severidad total = la más alta entre todos los steps
        top_severity_str = max(
            steps,
            key=lambda s: _SEVERITY_ORDER.get(s.severity, 0),
        ).severity
        total_severity = _STR_TO_SEVERITY.get(top_severity_str, Severity.INFO)

        # TechniqueMatch primario: primer step que no sea trust_policy
        primary_match = None
        for src, dst in zip(node_sequence[:-1], node_sequence[1:]):
            tm = self._graph.edges[src, dst].get("technique_match")
            if tm is not None:
                primary_match = tm
                break

        admin_label = _get_node_label(self._graph, self._admin_id)

        return EscalationPath(
            path_id=str(uuid.uuid4()),
            severity=total_severity,
            origin_arn=source_id,
            origin_name=source_label,
            target_arn=self._admin_id,
            target_name=admin_label,
            steps=steps,
            technique_match=primary_match,
        )

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------

    def _find_admin_node(self) -> str | None:
        for node_id, data in self._graph.nodes(data=True):
            node_obj: IAMNode | None = data.get("node")
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
    node_obj: IAMNode | None = data.get("node")
    if node_obj:
        return node_obj.label
    return node_id


def _evidence_to_strings(evidence: list) -> list[str]:
    """
    Convierte list[dict] de evidencia del builder a list[str] para PathStep.

    Formato: "iam:CreatePolicyVersion on * (via inline: test-policy)"
    """
    result = []
    for ev in evidence:
        if isinstance(ev, str):
            result.append(ev)
        elif isinstance(ev, dict):
            action      = ev.get("action", "unknown")
            resource    = ev.get("resource", "*")
            source_type = ev.get("source_type", "")
            source_name = ev.get("source_name", "")
            result.append(
                f"{action} on {resource} (via {source_type}: {source_name})"
            )
    return result


def _sort_by_severity(paths: list[EscalationPath]) -> list[EscalationPath]:
    """Ordena rutas de mayor a menor severidad."""
    return sorted(
        paths,
        key=lambda p: _SEVERITY_ORDER.get(p.severity.value, 0),
        reverse=True,
    )
