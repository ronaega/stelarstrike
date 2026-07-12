"""StelarStrike command-line interface."""

from __future__ import annotations

import asyncio
import logging

import typer
from rich.console import Console
from rich.table import Table

from stelarstrike.core.config import load_settings
from stelarstrike.core.orchestrator import Orchestrator
from stelarstrike.core.target import ScopeError
from stelarstrike.plugins import PLUGIN_REGISTRY

app = typer.Typer(
    name="stelarstrike",
    help="StelarStrike — modular, AI-assisted web vulnerability orchestration framework.",
    add_completion=False,
)
console = Console()

BANNER = r"""
                 ▒---------------------------
                   ░----- LET'S STRIKE ------
                    ▒---------- BABY ! ! ! --
       ░░            ░-----------------------
   ░░░▒░░░▒▒▓▓▒░     ░▒-----------██▓▒▓███---
 ░▒▓▓▓▓▓▓▓▓▓▓▓▒▓▒░     ▒------███▓▒░░▒▒▒▒▓██-
▒▓▓▓▓▒░░░░▒▓████▓▒░    ░----█▓▓▓▒░░░▒▒▒▒▒▒▒▒▓
▓▓▓▓▒░░░▒░ ░▒▓███▓░   ░----█▒▒▓▒░░▒▒▒▒▒▒▒▒▒▒▒
▓▓███▒░   ░░▒▓▓▒▒▓▒  ▒-----▓▒▒░░░▒▒▒▒▒▒▒▒░░░░
▓▓████▒░░▒▒▓█▓░░ ░░░-------▒▒░░░░░░░▒▒▒▒░░░░░
▓▓▓██████████▓  ░░▒--------░▒▒░░   ░░▒▒░░   ░
▒▒▒▒▒▒▓▓█████▓░░░---------▓░░░░░░░░░░▓█▓▒░░▒▓
░▒░░▓▓▓░░▒▓▓█▓▓-----------▓▒▒▒▒▒▒▒▒▒▒████████
░▒░ ░░▒░░░░░░▓▓------------▒▒▒▒▓▓▓▒▒▒▒▓▓▓▒▒▓█
░░▒▒▒▒▒░░░░░░▒▒------------▓░▒▓▓▓▒▒▒▒░░▓██▒▒▒
░░▒▒▒░░▒░░ ░░▒▓-------------▒▒▒▓▒▒░░░▒▒▒▒░░░▒
░░░▒▒▒░░░░░░  ▒-------------▒▒▒▓▒▒▒▒▒░░▒▓██▒▒
░░░░░░░░░      ░▒-----------░░░▒▒▒▒▒▒▒▒▒▒▓▓▒▒
░░░░             ░▓--------░░░░░░░▒▒▒▒▒▓▓▓▒▒▒
         S T E L A R S T R I K E
               by Stelariux
                v0.1.0-dev
─────────────────────────────────────────────
"""


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan, e.g. https://target.example.com/page?id=1"),
    config: str = typer.Option("config/config.yaml", "--config", "-c", help="Path to config.yaml"),
    formats: str = typer.Option("markdown,json", "--formats", help="Comma-separated report formats to write"),
    plugins_opt: str = typer.Option(
        None,
        "--plugins",
        "-p",
        help=(
            "Comma-separated plugin IDs to run for THIS scan only, e.g. --plugins sqli,xss. "
            "Overrides config.yaml's enabled/disabled flags for this run. "
            "Omit to scan with whatever config.yaml has enabled (all 8 plugins, by default)."
        ),
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show every request/payload each plugin tries — use this when a scan finds nothing and you need to see why."),
):
    """Run a scan against TARGET. Runs all config-enabled plugins by default; use --plugins to run only specific ones."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    console.print(BANNER, style="bold cyan", markup=False, highlight=False)

    settings = load_settings(config)

    plugin_filter: set[str] | None = None
    if plugins_opt:
        requested = {p.strip() for p in plugins_opt.split(",") if p.strip()}
        unknown = requested - set(PLUGIN_REGISTRY)
        if unknown:
            console.print(f"[bold red]Unknown plugin id(s):[/] {', '.join(sorted(unknown))}")
            console.print(f"Available: {', '.join(PLUGIN_REGISTRY)}")
            raise typer.Exit(code=1)
        plugin_filter = requested

    console.print(f"Scanning: [bold]{target}[/]")
    running = ", ".join(sorted(plugin_filter)) if plugin_filter else "all enabled in config.yaml"
    console.print(f"Engagement: [bold]{settings.engagement.name}[/] | AI: {'on' if settings.ai.enabled else 'off'} ({settings.ai.provider if settings.ai.enabled else 'n/a'}) | Discovery: {'on' if settings.discovery.enabled else 'off'} | Plugins: {running}")

    orchestrator = Orchestrator(settings)
    try:
        report = asyncio.run(orchestrator.run(target, plugin_filter=plugin_filter))
    except ScopeError as exc:
        console.print(f"[bold red]Scope error:[/] {exc}")
        raise typer.Exit(code=1)

    if orchestrator.matched_schema:
        console.print(f"[bold green]Pattern matched:[/] {orchestrator.matched_schema.name} — probe endpoints and sqli hints applied")

    _print_summary(report)

    written = []
    if "markdown" in formats:
        written.append(report.write_markdown())
    if "json" in formats:
        written.append(report.write_json())

    for path in written:
        console.print(f"[green]Report written:[/] {path}")


@app.command()
def schemas():
    """List all available alternative schema files in the schemas/ directory."""
    from pathlib import Path
    import yaml as _yaml
    schemas_dir = Path("schemas")
    if not schemas_dir.exists():
        console.print("[yellow]No schemas/ directory found.[/] Create it and add .yaml schema files.")
        return
    files = sorted(schemas_dir.glob("*.yaml"))
    if not files:
        console.print("[yellow]No schema files found in schemas/[/]")
        return
    table = Table(title="Alternative Schemas")
    table.add_column("File")
    table.add_column("Name")
    table.add_column("Fingerprints")
    table.add_column("Injections")
    for f in files:
        if f.name == "example.yaml":
            continue
        try:
            data = _yaml.safe_load(f.read_text())
            fps = ", ".join(
                next(iter(fp.values())) for fp in data.get("fingerprints", [])[:2]
            )
            injs = str(len(data.get("injections", [])))
            table.add_row(f.name, data.get("name", "?"), fps or "-", injs)
        except Exception:
            table.add_row(f.name, "[red]parse error[/]", "-", "-")
    console.print(table)
    console.print("\n[dim]See schemas/README.md for format and how to create schemas from writeups.[/]")


@app.command()
def plugins():
    """List all registered vulnerability plugins."""
    table = Table(title="StelarStrike Plugins")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Default Severity")
    for plugin_id, plugin_cls in PLUGIN_REGISTRY.items():
        table.add_row(plugin_id, plugin_cls.name, plugin_cls.default_severity)
    console.print(table)


@app.command()
def doctor(config: str = typer.Option("config/config.yaml", "--config", "-c")):
    """Sanity-check configuration, AI connectivity, and plugin registration."""
    console.print("[bold]Running StelarStrike diagnostics...[/]\n")

    try:
        settings = load_settings(config)
        console.print(f"[green]OK[/] Config loaded from {config}")
    except Exception as exc:
        console.print(f"[red]FAIL[/] Config load failed: {exc}")
        raise typer.Exit(code=1)

    console.print(f"[green]OK[/] {len(PLUGIN_REGISTRY)} plugin(s) registered: {', '.join(PLUGIN_REGISTRY)}")

    enabled = [pid for pid, cfg in settings.plugins.items() if cfg.enabled]
    console.print(f"[green]OK[/] {len(enabled)} plugin(s) enabled: {', '.join(enabled) or 'none'}")

    if not settings.engagement.scope:
        console.print("[yellow]WARN[/] No engagement.scope defined — all scan attempts will be refused.")
    else:
        console.print(f"[green]OK[/] Scope: {settings.engagement.scope}")

    if settings.ai.enabled:
        try:
            import litellm  # noqa: F401

            console.print(f"[green]OK[/] litellm installed; AI provider configured as '{settings.ai.provider}'")
        except ImportError:
            console.print("[yellow]WARN[/] AI enabled in config but litellm is not installed (`pip install litellm`)")
    else:
        console.print("[cyan]INFO[/] AI features disabled in config.")


def _print_summary(report) -> None:
    table = Table(title=f"Findings — {report.engagement_name}")
    table.add_column("Severity")
    table.add_column("Plugin")
    table.add_column("Title")
    table.add_column("Parameter")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    for f in sorted(report.findings, key=lambda x: severity_order.get(x.severity, 5)):
        table.add_row(f.severity.upper(), f.plugin, f.title, f.parameter or "-")

    console.print(table)
    console.print(f"[bold]{len(report.findings)}[/] total finding(s).")


if __name__ == "__main__":
    app()
