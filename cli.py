"""
iamspy CLI — entry point.

Commands:
  iamspy scan     Scan an AWS account and build the IAM attack graph
  iamspy report   Generate a report from a previous scan
  iamspy compare  Compare findings against AWS Security Hub
"""

import typer
from rich.console import Console

app = typer.Typer(
    name="iamspy",
    help="AWS IAM attack path analysis — find privilege escalation chains.",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    profile: str = typer.Option(None, "--profile", "-p", help="AWS profile to use"),
    account_id: str = typer.Option(None, "--account-id", help="Target AWS account ID"),
    output: str = typer.Option("report.json", "--output", "-o", help="Output file path"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json | markdown | graphml"),
) -> None:
    """Scan an AWS account and find IAM privilege escalation paths."""
    console.print("[bold yellow]iamspy[/] — scan started")
    console.print(f"  profile : {profile or 'default'}")
    console.print(f"  output  : {output} ({format})")
    console.print("\n[dim]Phase 2 (ingestion module) not yet implemented.[/dim]")


@app.command()
def report(
    input: str = typer.Argument(..., help="Path to a scan result JSON file"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown | json"),
) -> None:
    """Generate a human-readable report from a scan result."""
    console.print(f"[bold yellow]iamspy[/] — generating report from {input}")
    console.print("\n[dim]Phase 4 (output module) not yet implemented.[/dim]")


@app.command()
def compare(
    scan_file: str = typer.Argument(..., help="Path to iamspy scan result JSON"),
    region: str = typer.Option("us-east-1", "--region", "-r", help="AWS region for Security Hub"),
) -> None:
    """Compare iamspy findings against AWS Security Hub on the same account."""
    console.print("[bold yellow]iamspy[/] — comparing against Security Hub")
    console.print("\n[dim]Phase 4 (comparator module) not yet implemented.[/dim]")


def version_callback(value: bool) -> None:
    if value:
        from iamspy import __version__
        console.print(f"iamspy {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(None, "--version", "-v", callback=version_callback, is_eager=True),
) -> None:
    pass


if __name__ == "__main__":
    app()
