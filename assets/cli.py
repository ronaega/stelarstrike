"""StelarStrike command-line interface — v2 with agent support."""

from __future__ import annotations

import asyncio
import logging

import typer
from rich.console import Console
from rich.table import Table

from assets.core.config import load_settings
from assets.core.orchestrator import Orchestrator
from assets.core.target import ScopeError
from assets.plugins import PLUGIN_REGISTRY

app = typer.Typer(
    name="stelarstrike",
    help="StelarStrike — modular, AI-assisted web vulnerability orchestration framework.",
    add_completion=False,
    invoke_without_command=True,
)
console = Console()

VERSION = "0.2.0-dev"

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
                v0.2.0-dev
─────────────────────────────────────────────
"""

# ── scan ─────────────────────────────────────────────────────────────────

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan."),
    config: str = typer.Option("config/config.yaml", "--config", "-c", help="Path to config.yaml"),
    formats: str = typer.Option("markdown,json", "--formats", help="Report formats (comma-separated)"),
    plugins_opt: str = typer.Option(
        None, "--plugins", "-p",
        help="Comma-separated plugin IDs to run, e.g. --plugins sqli,xss",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show every payload and response."),
):
    """Run a vulnerability scan against TARGET."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    console.print(BANNER, style="bold cyan", markup=False, highlight=False)
    settings = load_settings(config if config != "config/config.yaml" else None)

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
    console.print(
        f"Engagement: [bold]{settings.engagement.name}[/] | "
        f"AI: {'on' if settings.ai.enabled else 'off'} | "
        f"Plugins: {running}"
    )

    orchestrator = Orchestrator(settings)
    try:
        report = asyncio.run(orchestrator.run(target, plugin_filter=plugin_filter))
    except ScopeError as exc:
        console.print(f"[bold red]Scope error:[/] {exc}")
        raise typer.Exit(code=1)

    if getattr(orchestrator, "matched_schema", None):
        console.print(f"[bold green]Pattern matched:[/] {orchestrator.matched_schema.name}")

    _print_summary(report)

    written = []
    if "markdown" in formats:
        written.append(report.write_markdown())
    if "json" in formats:
        written.append(report.write_json())
    for p in written:
        console.print(f"[green]Report written:[/] {p}")


# ── agent commands ────────────────────────────────────────────────────────

@app.command(name="createagent")
def createagent(
    name: str = typer.Argument(..., help="Agent name (2-7 alphanumeric chars, no 'stelarstrike' or 'agent')"),
    target: str = typer.Argument(..., help="Target URL this agent will operate on"),
):
    """Create a new agent. Target is automatically authorized for active scanning."""
    from assets.core.agent import create_agent  # noqa: PLC0415
    msg = create_agent(name, target)
    if msg.startswith("Error") or msg == "The agent exists":
        console.print(f"[bold red]{msg}[/]")
        raise typer.Exit(code=1)
    console.print(f"[bold green]{msg}[/]")


@app.command(name="deleteagent")
def deleteagent(
    name: str = typer.Argument(..., help="Agent name to delete"),
):
    """Delete an existing agent and its conversation history."""
    from assets.core.agent import delete_agent  # noqa: PLC0415
    msg = delete_agent(name)
    if msg.startswith("Error"):
        console.print(f"[bold red]{msg}[/]")
        raise typer.Exit(code=1)
    console.print(f"[bold green]{msg}[/]")


@app.command(name="agents")
def agents_list():
    """List all agents and their assigned targets."""
    from assets.core.agent import list_agents  # noqa: PLC0415
    rows = list_agents()
    if not rows:
        console.print("[dim]No agents found. Create one with: stelarstrike --createagent <name> <target>[/]")
        return
    table = Table(title="Agents")
    table.add_column("Name", style="bold cyan")
    table.add_column("Target")
    table.add_column("Created")
    table.add_column("Last Chat")
    table.add_column("Chars", justify="right")
    for a in rows:
        table.add_row(
            a["name"], a["target"], a["created"][:16],
            a["last_chat"][:16], a["total_response_chars"],
        )
    console.print(table)


# ── skills / tools / schemas ──────────────────────────────────────────────

@app.command(name="skills")
def skills_list():
    """List all available skills and their descriptions."""
    from assets.core.agent import list_skills  # noqa: PLC0415
    rows = list_skills()
    table = Table(title="StelarStrike Skills")
    table.add_column("Skill", style="bold")
    table.add_column("Description")
    for s in rows:
        table.add_row(s["name"], s["description"])
    console.print(table)
    console.print("\n[dim]Skills are used automatically by agents during action execution.[/]")


@app.command(name="tools")
def tools_list():
    """List all available tools and their descriptions."""
    from assets.core.agent import list_tools  # noqa: PLC0415
    rows = list_tools()
    if not rows:
        console.print("[yellow]No tools found.[/]")
        return
    table = Table(title="StelarStrike Tools")
    table.add_column("Tool", style="bold")
    table.add_column("Category")
    table.add_column("Description")
    for t in rows:
        table.add_row(t["name"], t.get("category", ""), t.get("description", "")[:80])
    console.print(table)


@app.command()
def schemas():
    """List all available alternative schema files."""
    from pathlib import Path  # noqa: PLC0415
    import yaml as _yaml  # noqa: PLC0415
    schemas_dir = Path("schemas")
    if not schemas_dir.exists():
        console.print("[yellow]No schemas/ directory found.[/]")
        return
    files = sorted(schemas_dir.glob("*.yaml"))
    if not files:
        console.print("[yellow]No schema files found in schemas/[/]")
        return
    table = Table(title="Alternative Schemas")
    table.add_column("File")
    table.add_column("Name")
    table.add_column("Fingerprints")
    for f in files:
        try:
            data = _yaml.safe_load(f.read_text())
            fps = ", ".join(next(iter(fp.values())) for fp in data.get("fingerprints", [])[:2])
            table.add_row(f.name, data.get("name", "?"), fps or "-")
        except Exception:  # noqa: BLE001
            table.add_row(f.name, "[red]parse error[/]", "-")
    console.print(table)


# ── other commands ────────────────────────────────────────────────────────

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


@app.command(name="version")
def version():
    """Show the current version of StelarStrike."""
    console.print(f"StelarStrike [bold cyan]{VERSION}[/]")


@app.command()
def doctor(config: str = typer.Option("config/config.yaml", "--config", "-c")):
    """Sanity-check configuration, AI connectivity, and plugin registration."""
    console.print("[bold]Running StelarStrike diagnostics...[/]\n")
    try:
        settings = load_settings(config)
        console.print(f"[green]OK[/] Config loaded from {config}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]FAIL[/] Config load failed: {exc}")
        raise typer.Exit(code=1)

    console.print(f"[green]OK[/] {len(PLUGIN_REGISTRY)} plugin(s) registered: {', '.join(PLUGIN_REGISTRY)}")

    enabled = [pid for pid, cfg in settings.plugins.items() if cfg.enabled]
    console.print(f"[green]OK[/] {len(enabled)} plugin(s) enabled: {', '.join(enabled) or 'none'}")

    if not settings.engagement.scope:
        console.print("[yellow]WARN[/] No engagement.scope defined.")
    else:
        console.print(f"[green]OK[/] Scope: {settings.engagement.scope}")

    if settings.ai.enabled:
        import shutil as _shutil  # noqa: PLC0415
        opencode_path = _shutil.which("opencode")
        if opencode_path:
            console.print(f"[green]OK[/] OpenCode at '{opencode_path}'; model: '{settings.ai.provider}'")
        else:
            console.print(
                "[yellow]WARN[/] OpenCode not installed. "
                "Run: curl -fsSL https://opencode.ai/install | bash"
            )
    else:
        console.print("[cyan]INFO[/] AI features disabled.")


# ── agent chat (invoked from __main__.py, not a Typer command) ───────────

def run_agent_chat(agent_name: str, raw_prompt: str | None) -> None:
    """Handle `stelarstrike <agent> "<prompt>"` invocations."""
    from assets.core.agent import (  # noqa: PLC0415
        agent_exists,
        handle_prompt,
        validate_name,
    )

    # Validate agent name
    err = validate_name(agent_name)
    if err:
        console.print(f"[bold red]{err}[/]")
        raise SystemExit(1)

    # Agent must exist
    if not agent_exists(agent_name):
        console.print(f"[bold red]Error: agent '{agent_name}' does not exist.[/]")
        console.print(f"Create it with: stelarstrike --createagent {agent_name} <target>")
        raise SystemExit(1)

    # Prompt is required and must be quoted (passed as a single string)
    if raw_prompt is None:
        console.print('[bold red]Error: prompt is required. Usage: stelarstrike <agent> "<prompt>"[/]')
        raise SystemExit(1)

    # Dispatch
    response, rtype = handle_prompt(agent_name, raw_prompt)

    # Show BANNER for action-related responses
    if rtype in ("clarification", "action"):
        console.print(BANNER, style="bold cyan", markup=False, highlight=False)

    console.print(f"\n[bold cyan]Agent {agent_name}:[/]\n")
    console.print(response)
    console.print()

    if rtype == "clarification":
        console.print("[dim]Reply yes to proceed or no to cancel.[/]")


# ── internals ─────────────────────────────────────────────────────────────

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
