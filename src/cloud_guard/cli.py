import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

# Ensure scanners are registered
import cloud_guard.scanners.aws_scanner  # noqa: F401
import cloud_guard.scanners.k8s_scanner  # noqa: F401
from cloud_guard.core.config import settings
from cloud_guard.scanners.registry import scanner_registry

app = typer.Typer(name="cloud-guard", help="Cloud Security Posture Management CLI")
console = Console()


@app.command()
def scan(
    provider: str = typer.Option("aws", help="Cloud provider to scan"),
    compliance: str | None = typer.Option(None, help="Compliance framework"),
    output: str = typer.Option("table", help="Output format: table, json"),
):
    """Run a security scan against a cloud provider."""
    if provider not in scanner_registry:
        console.print(f"[red]Unknown provider: {provider}[/red]")
        console.print(f"Available: {', '.join(scanner_registry.keys())}")
        raise typer.Exit(1)

    scanner_cls = scanner_registry[provider]
    scanner = scanner_cls()

    console.print(f"[bold blue]Scanning {provider}...[/bold blue]")
    result = asyncio.run(scanner.scan(compliance_framework=compliance))

    table = Table(title=f"Cloud Guard — {provider.upper()} Scan Results")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Title")
    table.add_column("Resource")
    table.add_column("Control")

    severity_colors = {
        "critical": "red",
        "high": "yellow",
        "medium": "blue",
        "low": "green",
        "info": "dim",
    }

    for f in result.findings:
        color = severity_colors.get(f.severity.value, "white")
        table.add_row(
            f.rule_id,
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.title,
            f.resource_id,
            f.compliance_control or "-",
        )

    console.print(table)
    console.print(
        f"\n[bold]Summary:[/bold] {len(result.findings)} findings "
        f"({result.critical_count} critical, {result.high_count} high)"
    )

    if result.errors:
        console.print(f"\n[yellow]Errors ({len(result.errors)}):[/yellow]")
        for err in result.errors:
            console.print(f"  - {err}")


@app.command()
def serve(
    host: str = typer.Option(settings.api_host, help="Bind host"),
    port: int = typer.Option(settings.api_port, help="Bind port"),
):
    """Start the Cloud Guard API server."""
    import uvicorn

    console.print(f"[bold green]Starting Cloud Guard API on {host}:{port}[/bold green]")
    uvicorn.run("cloud_guard.api.app:app", host=host, port=port, reload=settings.debug)


@app.command()
def init():
    """Initialize Cloud Guard configuration."""
    env_example = Path(".env.example")
    env_file = Path(".env")

    if not env_file.exists() and env_example.exists():
        env_file.write_text(env_example.read_text())
        console.print("[green].env file created from .env.example[/green]")
    else:
        console.print("[yellow].env file already exists[/yellow]")

    console.print("[bold green]Cloud Guard initialized![/bold green]")
    console.print("Edit .env with your cloud provider credentials, then run: cloud-guard scan")


if __name__ == "__main__":
    app()
