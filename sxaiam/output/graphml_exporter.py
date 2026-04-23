"""
sxaiam/output/graphml_exporter.py

Exporta el grafo de ataque IAM a formato GraphML.

GraphML es un estándar XML para grafos compatible con:
  - Gephi (visualización y análisis de grafos)
  - yEd Graph Editor (diagramas profesionales)
  - Cytoscape (análisis de redes)
  - NetworkX (importación directa)

El grafo exportado preserva:
  - Todos los nodos con sus atributos (type, label, account_id)
  - Todas las aristas con su evidencia (technique, severity, evidence)
  - La dirección de las aristas (DiGraph)

Uso típico después de sxaiam scan:
  gephi report.graphml
  # → visualización interactiva del grafo de ataque
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import networkx as nx

from sxaiam.graph.nodes import IAMNode

logger = logging.getLogger(__name__)


class GraphMLExporter:
    """
    Exporta el DiGraph del AttackGraph a formato GraphML.

    Uso básico:
        exporter = GraphMLExporter()
        exporter.export(G, Path("report.graphml"))
    """

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def export(
        self,
        graph: nx.DiGraph,
        output_path: Path,
    ) -> None:
        """
        Exporta el grafo a GraphML en output_path.

        Args:
            graph:       DiGraph producido por AttackGraph.build().
            output_path: Ruta del archivo de salida (.graphml).
        """
        export_graph = self._prepare_graph(graph)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        nx.write_graphml(export_graph, str(output_path))

        logger.info(
            "GraphML exportado: %s (%d nodos, %d aristas)",
            output_path,
            export_graph.number_of_nodes(),
            export_graph.number_of_edges(),
        )

    def to_graphml_string(self, graph: nx.DiGraph) -> str:
        """
        Devuelve el GraphML como string — útil para testing.
        """
        import io
        export_graph = self._prepare_graph(graph)
        buf = io.BytesIO()
        nx.write_graphml(export_graph, buf)
        return buf.getvalue().decode("utf-8")

    # ------------------------------------------------------------------
    # Preparación del grafo
    # ------------------------------------------------------------------

    def _prepare_graph(self, graph: nx.DiGraph) -> nx.DiGraph:
        """
        Crea una copia del grafo con atributos serializables a GraphML.

        networkx.write_graphml requiere que todos los atributos sean
        tipos primitivos (str, int, float, bool) — no objetos Python.
        Esta función convierte los atributos de nodos y aristas.
        """
        export_graph = nx.DiGraph()

        # Nodos — extraer atributos del objeto IAMNode
        for node_id, data in graph.nodes(data=True):
            node_obj: Optional[IAMNode] = data.get("node")
            if node_obj:
                export_graph.add_node(
                    node_id,
                    label=node_obj.label,
                    node_type=node_obj.node_type,
                    account_id=node_obj.account_id or "",
                )
            else:
                export_graph.add_node(node_id, label=node_id, node_type="unknown")

        # Aristas — serializar evidence como string JSON
        import json
        for src, dst, edge_data in graph.edges(data=True):
            evidence = edge_data.get("evidence", [])
            attack_steps = edge_data.get("attack_steps", [])

            export_graph.add_edge(
                src,
                dst,
                technique=edge_data.get("technique", "unknown"),
                severity=edge_data.get("severity", "INFO"),
                # GraphML no soporta listas — serializamos a JSON string
                evidence=json.dumps(evidence, ensure_ascii=False),
                attack_steps=json.dumps(attack_steps, ensure_ascii=False),
            )

        return export_graph
