"""
sxaiam.providers.gcp.cli
========================
Subcomando ``sxaiam gcp``. Se monta en ``sxaiam/cli.py`` con ``app.add_typer``.

    sxaiam gcp scan --snapshot proyecto.json --output report.json [--format markdown]

Todo el texto de consola es ASCII (mismo criterio que el commit 6c3bc6d,
"Fix README and CLI text encoding") y pasa por la consola de Rich de
``sxaiam.cli``. Los datos del snapshot se escapan para que Rich no los
interprete como markup.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import typer
from rich.markup import escape

from sxaiam.providers.gcp.resolver import IgnoredBinding, IgnoredReason

gcp_app = typer.Typer(
    name="gcp",
    help="GCP IAM attack path analysis (proof of concept, offline snapshot).",
    add_completion=False,
    no_args_is_help=True,
)


@gcp_app.command("scan")
def scan(
    snapshot: Path = typer.Option(
        ..., "--snapshot", "-s",
        help="GCP snapshot JSON (gcloud get-iam-policy output, see docs)",
    ),
    output: Path = typer.Option(
        Path("report.json"), "--output", "-o",
        help="Output file path",
    ),
    format: str = typer.Option(
        "json", "--format", "-f",
        help="Output format: json | markdown",
    ),
    cutoff: int = typer.Option(
        5, "--cutoff",
        help="Maximum path depth for BFS (default: 5)",
    ),
) -> None:
    """Scan a GCP project snapshot and find IAM privilege escalation paths."""
    # Import diferido: sxaiam.cli importa este módulo para montar el subcomando
    from sxaiam.cli import _print_summary_table, console
    from sxaiam.graph.pathfinder import PathFinder
    from sxaiam.providers.gcp.builder import (
        GCPAttackGraph,
        filter_already_admin,
        is_already_admin_node,
    )
    from sxaiam.providers.gcp.loader import GCPSnapshotError, load_snapshot
    from sxaiam.providers.gcp.resolver import GCPResolver

    fmt = format.lower()
    if fmt not in ("json", "markdown"):
        console.print(f"[red]X Unknown format:[/] {escape(format)}. Use json | markdown")
        raise typer.Exit(code=1)

    # Header
    console.print()
    console.print("[bold yellow]sxaiam[/] - GCP IAM Attack Path Analysis (PoC)")
    console.print(f"  snapshot : [cyan]{escape(str(snapshot))}[/]")
    console.print(f"  output   : [cyan]{escape(str(output))}[/] ([dim]{fmt}[/])")
    console.print(f"  cutoff   : [dim]{cutoff} hops[/]")
    console.print()

    # Step 1: Snapshot
    console.print("[bold]1/4[/] Loading snapshot...")
    if not snapshot.exists():
        console.print(f"[red]X Snapshot not found:[/] {escape(str(snapshot))}")
        raise typer.Exit(code=1)
    try:
        snap = load_snapshot(snapshot)
    except (GCPSnapshotError, OSError) as exc:
        console.print(f"[red]X Snapshot load failed:[/] {escape(str(exc))}")
        raise typer.Exit(code=1)

    console.print(
        f"  [green]OK[/] {len(snap.project_bindings)} project bindings, "
        f"{len(snap.service_accounts)} service accounts - "
        f"project [cyan]{escape(snap.project_id)}[/]"
    )

    # Step 2: Resolver
    console.print("[bold]2/4[/] Resolving effective permissions...")
    resolver = GCPResolver(snap)
    principals = resolver.resolve_all()
    console.print(
        f"  [green]OK[/] {len(principals)} principals resolved, "
        f"{len(resolver.ignored)} binding(s) ignored"
    )

    # Step 3: Grafo + BFS
    console.print("[bold]3/4[/] Building attack graph and finding paths...")
    builder = GCPAttackGraph()
    G = builder.build(snap, principals)
    raw_paths = PathFinder(G, cutoff=cutoff).find_all_paths()
    paths = filter_already_admin(raw_paths, G)
    console.print(
        f"  [green]OK[/] {G.number_of_nodes()} nodes, {G.number_of_edges()} edges - "
        f"[bold]{len(paths)} escalation path(s) found[/] "
        f"([dim]{len(raw_paths) - len(paths)} from already-admin origins filtered[/])"
    )

    # Step 4: Export (exportadores AWS sin cambios)
    console.print(f"[bold]4/4[/] Exporting results ({fmt})...")
    version = _installed_version()
    try:
        if fmt == "json":
            from sxaiam.output.json_exporter import JSONExporter
            JSONExporter(account_id=snap.project_id, version=version).export(paths, output)
        else:
            from sxaiam.output.markdown_exporter import MarkdownExporter
            MarkdownExporter(account_id=snap.project_id, version=version).export(paths, output)
    except OSError as exc:
        console.print(f"[red]X Export failed:[/] {escape(str(exc))}")
        raise typer.Exit(code=1)

    console.print(f"  [green]OK[/] Saved to [cyan]{escape(str(output))}[/]")

    # Resumen
    _print_summary_table(paths)
    _print_ignored(resolver.ignored)
    _print_already_admin(sorted(n for n in G.nodes if is_already_admin_node(G, n)))
    _print_dropped_edges(builder.dropped_edges)


def _installed_version() -> str:
    # sxaiam no tiene __init__.py (namespace package): no hay sxaiam.__version__
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("sxaiam")
    except PackageNotFoundError:
        return "unknown"


# ---------------------------------------------------------------------------
# Resumen final
# ---------------------------------------------------------------------------

_REASON_ORDER = list(IgnoredReason)


def _print_ignored(ignored: list[IgnoredBinding]) -> None:
    from sxaiam.cli import console

    if not ignored:
        console.print("[green]OK[/] No bindings ignored.")
        return

    by_reason: dict[IgnoredReason, list[IgnoredBinding]] = defaultdict(list)
    for record in ignored:
        by_reason[record.reason].append(record)

    console.print(f"[yellow]WARNING[/] {len(ignored)} binding(s) ignored (not evaluated):")
    for reason in _REASON_ORDER:
        records = by_reason.get(reason)
        if not records:
            continue
        console.print(f"  [bold]{reason.value}[/] ({len(records)})")
        for r in records:
            who = f"{escape(r.member)} " if r.member else ""
            console.print(f"    - {who}{escape(r.role)} on {escape(r.resource)}")
    console.print()


def _print_already_admin(members: list[str]) -> None:
    from sxaiam.cli import console

    if not members:
        return
    console.print(
        f"[bold]Already admin[/] (roles/owner, not escalation paths): {len(members)}"
    )
    for member in members:
        console.print(f"    - {escape(member)}")
    console.print()


def _print_dropped_edges(dropped: list[tuple[str, str, str]]) -> None:
    from sxaiam.cli import console

    if not dropped:
        return
    console.print(f"[yellow]WARNING[/] {len(dropped)} edge(s) dropped (target not in graph):")
    for source, target, technique in dropped:
        console.print(f"    - {escape(technique)}: {escape(source)} -> {escape(target)}")
    console.print()
