"""
sxaiam CLI — entry point.

Commands:
  sxaiam scan     Scan an AWS account and build the IAM attack graph
  sxaiam report   Generate a report from a previous scan
  sxaiam compare  Compare findings against AWS Security Hub
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich import box

app = typer.Typer(
    name="sxaiam",
    help="AWS IAM attack path analysis — find privilege escalation chains.",
    add_completion=False,
)
console = Console()


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@app.command()
def scan(
    profile: str = typer.Option(
        None, "--profile", "-p",
        help="AWS profile to use (from ~/.aws/credentials)",
    ),
    account_id: str = typer.Option(
        None, "--account-id",
        help="Target AWS account ID (optional — auto-detected if omitted)",
    ),
    output: str = typer.Option(
        "report.json", "--output", "-o",
        help="Output file path",
    ),
    format: str = typer.Option(
        "json", "--format", "-f",
        help="Output format: json | markdown | graphml",
    ),
    cutoff: int = typer.Option(
        5, "--cutoff",
        help="Maximum path depth for BFS (default: 5)",
    ),
) -> None:
    """Scan an AWS account and find IAM privilege escalation paths."""

    # ── Header ──────────────────────────────────────────────────────────
    console.print()
    console.print("[bold yellow]sxaiam[/] — IAM Attack Path Analysis")
    console.print(f"  profile : [cyan]{profile or 'default'}[/]")
    console.print(f"  output  : [cyan]{output}[/] ([dim]{format}[/])")
    console.print(f"  cutoff  : [dim]{cutoff} hops[/]")
    console.print()

    # ── Step 1: Ingestion ────────────────────────────────────────────────
    console.print("[bold]1/4[/] Collecting IAM data from AWS...")
    try:
        from sxaiam.ingestion.client import IngestionClient
        client = IngestionClient.from_profile(profile) if profile else IngestionClient()
        snapshot = client.collect()
    except Exception as exc:
        console.print(f"[red]✗ Ingestion failed:[/] {exc}")
        raise typer.Exit(code=1)

    detected_account = account_id or snapshot.account_id or "unknown"
    console.print(
        f"  [green]✓[/] {len(snapshot.users)} users, "
        f"{len(snapshot.roles)} roles, "
        f"{len(snapshot.groups)} groups — "
        f"account [cyan]{detected_account}[/]"
    )

    # ── Step 2: Policy Resolution ────────────────────────────────────────
    console.print("[bold]2/4[/] Resolving effective permissions...")
    try:
        from sxaiam.resolver.engine import PolicyResolver
        resolved = PolicyResolver(snapshot).resolve_all()
    except Exception as exc:
        console.print(f"[red]✗ Resolver failed:[/] {exc}")
        raise typer.Exit(code=1)

    console.print(f"  [green]✓[/] {len(resolved)} identities resolved")

    # ── Step 3: Graph + BFS ──────────────────────────────────────────────
    console.print("[bold]3/4[/] Building attack graph and finding paths...")
    try:
        from sxaiam.graph.builder import AttackGraph
        from sxaiam.graph.pathfinder import PathFinder

        G      = AttackGraph().build(snapshot, list(resolved.values()))
        finder = PathFinder(G, cutoff=cutoff)
        paths  = finder.find_all_paths()
    except Exception as exc:
        console.print(f"[red]✗ Graph engine failed:[/] {exc}")
        raise typer.Exit(code=1)

    console.print(
        f"  [green]✓[/] {G.number_of_nodes()} nodes, "
        f"{G.number_of_edges()} edges — "
        f"[bold]{len(paths)} escalation path(s) found[/]"
    )

    # ── Step 4: Export ───────────────────────────────────────────────────
    console.print(f"[bold]4/4[/] Exporting results ({format})...")
    output_path = Path(output)

    try:
        fmt = format.lower()
        if fmt == "json":
            from sxaiam.output.json_exporter import JSONExporter
            JSONExporter(account_id=detected_account).export(paths, output_path)

        elif fmt == "markdown":
            from sxaiam.output.markdown_exporter import MarkdownExporter
            MarkdownExporter(account_id=detected_account).export(paths, output_path)

        elif fmt == "graphml":
            from sxaiam.output.graphml_exporter import GraphMLExporter
            GraphMLExporter().export(G, output_path)

        else:
            console.print(f"[red]✗ Unknown format:[/] {format}. Use json | markdown | graphml")
            raise typer.Exit(code=1)

    except Exception as exc:
        console.print(f"[red]✗ Export failed:[/] {exc}")
        raise typer.Exit(code=1)

    console.print(f"  [green]✓[/] Saved to [cyan]{output_path}[/]")

    # ── Summary table ────────────────────────────────────────────────────
    _print_summary_table(paths)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

@app.command()
def report(
    input: str = typer.Argument(..., help="Path to a scan result JSON file"),
    output: str = typer.Option(
        None, "--output", "-o",
        help="Output file (default: stdout)",
    ),
    format: str = typer.Option(
        "markdown", "--format", "-f",
        help="Output format: markdown | json",
    ),
) -> None:
    """Generate a human-readable report from a scan result JSON."""

    console.print()
    console.print(f"[bold yellow]sxaiam[/] — generating report from [cyan]{input}[/]")

    input_path = Path(input)
    if not input_path.exists():
        console.print(f"[red]✗ File not found:[/] {input}")
        raise typer.Exit(code=1)

    # Cargar paths desde el JSON de scan
    try:
        paths = _load_paths_from_json(input_path)
    except Exception as exc:
        console.print(f"[red]✗ Failed to load scan file:[/] {exc}")
        raise typer.Exit(code=1)

    console.print(f"  [green]✓[/] Loaded {len(paths)} path(s)")

    # Generar output
    fmt = format.lower()
    if fmt == "markdown":
        from sxaiam.output.markdown_exporter import MarkdownExporter
        exporter = MarkdownExporter()
        if output:
            exporter.export(paths, Path(output))
            console.print(f"  [green]✓[/] Report saved to [cyan]{output}[/]")
        else:
            console.print(exporter.to_markdown(paths))

    elif fmt == "json":
        from sxaiam.output.json_exporter import JSONExporter
        exporter = JSONExporter()
        if output:
            exporter.export(paths, Path(output))
            console.print(f"  [green]✓[/] Report saved to [cyan]{output}[/]")
        else:
            console.print(exporter.to_json(paths))

    else:
        console.print(f"[red]✗ Unknown format:[/] {format}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------

@app.command()
def compare(
    scan_file: str = typer.Argument(
        ..., help="Path to sxaiam scan result JSON"
    ),
    findings_file: str = typer.Option(
        ..., "--findings", "-f",
        help="Path to Security Hub findings JSON (aws securityhub get-findings)",
    ),
    output: str = typer.Option(
        None, "--output", "-o",
        help="Output file for the gap report (default: stdout)",
    ),
) -> None:
    """Compare sxaiam findings against AWS Security Hub on the same account."""

    console.print()
    console.print("[bold yellow]sxaiam[/] — Detection Gap Analysis")
    console.print(f"  sxaiam scan : [cyan]{scan_file}[/]")
    console.print(f"  SH findings : [cyan]{findings_file}[/]")
    console.print()

    # Cargar paths de sxaiam
    scan_path = Path(scan_file)
    if not scan_path.exists():
        console.print(f"[red]✗ Scan file not found:[/] {scan_file}")
        raise typer.Exit(code=1)

    try:
        paths = _load_paths_from_json(scan_path)
    except Exception as exc:
        console.print(f"[red]✗ Failed to load scan file:[/] {exc}")
        raise typer.Exit(code=1)

    # Cargar findings de Security Hub
    sh_path = Path(findings_file)
    if not sh_path.exists():
        console.print(f"[red]✗ Security Hub findings file not found:[/] {findings_file}")
        raise typer.Exit(code=1)

    from sxaiam.findings.comparator import SecurityHubComparator
    comparator = SecurityHubComparator()
    try:
        comparator.load_findings_from_file(sh_path)
    except Exception as exc:
        console.print(f"[red]✗ Failed to load Security Hub findings:[/] {exc}")
        raise typer.Exit(code=1)

    console.print(
        f"  [green]✓[/] {len(paths)} sxaiam path(s), "
        f"{len(comparator._findings)} Security Hub finding(s) loaded"
    )

    # Comparar
    report_obj = comparator.compare(paths)

    # Imprimir scoring ejecutivo
    _print_executive_scoring(report_obj)

    # Output
    md = report_obj.to_markdown()
    if output:
        Path(output).write_text(md, encoding="utf-8")
        console.print(f"\n  [green]✓[/] Gap report saved to [cyan]{output}[/]")
    else:
        console.print()
        console.print(md)


# ---------------------------------------------------------------------------
# version callback
# ---------------------------------------------------------------------------

def version_callback(value: bool) -> None:
    if value:
        try:
            from sxaiam import __version__
            console.print(f"sxaiam {__version__}")
        except ImportError:
            console.print("sxaiam 0.1.0")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None, "--version", "-v",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    pass


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------

def _print_summary_table(paths: list) -> None:
    """Imprime tabla resumen de rutas encontradas en la terminal."""
    if not paths:
        console.print("\n[green]✓ No escalation paths found.[/]")
        return

    console.print()
    table = Table(
        title="Escalation Paths Found",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Origin",   width=30)
    table.add_column("Steps",    width=6, justify="center")
    table.add_column("Techniques", width=35)

    severity_colors = {
        "CRITICAL": "red",
        "HIGH":     "orange3",
        "MEDIUM":   "yellow",
        "LOW":      "green",
    }

    for path in paths:
        sev   = path.severity.value
        color = severity_colors.get(sev, "white")
        table.add_row(
            f"[{color}]{sev}[/]",
            path.origin_name,
            str(path.step_count),
            ", ".join(path.techniques_used),
        )

    console.print(table)
    console.print()


def _print_executive_scoring(report) -> None:
    """Imprime scoring ejecutivo del gap de detección."""
    console.print()

    table = Table(
        title="Executive Detection Scoring",
        box=box.ROUNDED,
        show_header=False,
    )
    table.add_column("Metric", style="bold", width=35)
    table.add_column("Value",  width=20)

    # Calcular critical missed
    critical_missed = sum(
        1 for c in report.missed
        if c.path.severity.value == "CRITICAL"
    )

    gap_color = "red" if report.gap_percentage > 50 else "yellow" if report.gap_percentage > 20 else "green"

    table.add_row("sxaiam paths found",         str(report.total_sxaiam_paths))
    table.add_row("Security Hub findings loaded", str(report.total_sh_findings))
    table.add_row("Detection Coverage",          f"{report.coverage_percentage}%")
    table.add_row(
        "Escalation Blind Spots",
        f"[{gap_color}]{report.gap_percentage}%[/]"
    )
    table.add_row(
        "Critical Paths Not Detected",
        f"[red]{critical_missed}[/]" if critical_missed > 0 else "0"
    )
    table.add_row("Paths Not Correlated",        str(len(report.missed)))
    table.add_row("Paths Partially Correlated",  str(len(report.partial)))

    console.print(table)


def _load_paths_from_json(path: Path) -> list:
    """
    Carga EscalationPaths desde un JSON de scan de sxaiam.

    Nota: el JSON de scan guarda los paths serializados como dicts.
    Para el comando report y compare los reconstruimos como objetos
    mínimos que los exporters y el comparador pueden consumir.
    """
    data = json.loads(path.read_text(encoding="utf-8"))

    # El JSON tiene {"metadata": {...}, "paths": [...]}
    raw_paths = data.get("paths", [])

    # Reconstruir como objetos compatibles con los exporters
    from sxaiam.findings.escalation_path import EscalationPath, PathStep
    from sxaiam.findings.technique_base import Severity

    paths = []
    for rp in raw_paths:
        steps = [
            PathStep(
                step_number=s["step"],
                from_arn=s["from_arn"],
                from_name=s["from_name"],
                to_arn=s["to_arn"],
                to_name=s["to_name"],
                technique_id=s["technique"],
                technique_name=s["technique"],
                severity=s.get("severity", "INFO"),
                evidence=s.get("evidence", []),
                api_calls=s.get("api_calls", []),
            )
            for s in rp.get("steps", [])
        ]
        sev_str = rp.get("severity", "INFO")
        try:
            severity = Severity(sev_str)
        except ValueError:
            severity = Severity.INFO

        ep = EscalationPath(
            path_id=rp["path_id"],
            severity=severity,
            origin_arn=rp["origin"]["arn"],
            origin_name=rp["origin"]["name"],
            target_arn=rp["target"]["arn"],
            target_name=rp["target"]["name"],
            steps=steps,
        )
        paths.append(ep)

    return paths


if __name__ == "__main__":
    app()
