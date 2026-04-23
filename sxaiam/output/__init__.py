"""
sxaiam/output/__init__.py

Módulo de exportación de resultados de sxaiam.

Exports públicos:
    JSONExporter     — serializa rutas a JSON estructurado
    MarkdownExporter — genera reporte Markdown legible
    GraphMLExporter  — exporta grafo a GraphML para visualización

Uso típico:
    from sxaiam.output import JSONExporter, MarkdownExporter

    json_exp = JSONExporter(account_id="123456789012")
    json_exp.export(paths, Path("report.json"))

    md_exp = MarkdownExporter(account_id="123456789012")
    md_exp.export(paths, Path("report.md"))
"""

from sxaiam.output.json_exporter import JSONExporter
from sxaiam.output.markdown_exporter import MarkdownExporter
from sxaiam.output.graphml_exporter import GraphMLExporter

__all__ = [
    "JSONExporter",
    "MarkdownExporter",
    "GraphMLExporter",
]
