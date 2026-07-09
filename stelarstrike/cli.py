from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from stelarstrike import __version__
from stelarstrike.plugins import PLUGIN_REGISTRY

app = typer.Typer(help="Modular web vulnerability orchestration framework.")
console = Console()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Show version and exit."),
) -> None:
    if version:
        console.print(f"StelarStrike {__version__}")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit()


@app.command()
def plugins() -> None:
    """List registered vulnerability plugins."""
    table = Table(title="Registered Plugins")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Severity")

    for plugin_id, plugin_cls in sorted(PLUGIN_REGISTRY.items()):
        table.add_row(plugin_id, plugin_cls.name, plugin_cls.default_severity)

    console.print(table)


@app.command()
def doctor() -> None:
    """Run lightweight environment checks."""
    console.print("StelarStrike doctor: OK")
    console.print(f"Registered plugins: {len(PLUGIN_REGISTRY)}")


@app.command()
def scan(target: str) -> None:
    """Placeholder scan command for the initial package scaffold."""
    console.print(f"Scan orchestration is not implemented yet for {target}")
    raise typer.Exit(code=2)
