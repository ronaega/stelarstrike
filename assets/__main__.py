"""
StelarStrike entry point.

Handles two special routing cases before Typer sees the args:

1. `--X` commands (createagent, deleteagent, agents, skills, tools, version)
   are registered in Typer as plain names. We strip the `--` here so the
   user can type either form:
     stelarstrike --skills       (user-facing, documented style)
     stelarstrike skills         (also works)

2. `stelarstrike <agent> "<prompt>"` — if the first argument is an alphanumeric
   2-7 char token that is not a known command, treat it as an agent name.
"""

from __future__ import annotations

import sys

# Map --X → X for commands that are documented with double-dash prefix
_DASH_MAP: dict[str, str] = {
    "--createagent": "createagent",
    "--deleteagent": "deleteagent",
    "--agents":      "agents",
    "--skills":      "skills",
    "--tools":       "tools",
    "--version":     "version",
}

# All known Typer command names (plain, no dashes)
_KNOWN_COMMANDS = {
    "scan", "plugins", "schemas", "doctor",
    "createagent", "deleteagent", "agents",
    "skills", "tools", "version",
    "--help", "-h",
}


def main() -> None:
    args = list(sys.argv[1:])

    if not args:
        from assets.cli import app  # noqa: PLC0415
        app()
        return

    first = args[0]

    # Translate --X → X so Typer finds the command
    if first in _DASH_MAP:
        sys.argv[1] = _DASH_MAP[first]
        from assets.cli import app  # noqa: PLC0415
        app()
        return

    # Agent chat: `stelarstrike <agentname> "<prompt>"`
    if (
        not first.startswith("-")
        and first not in _KNOWN_COMMANDS
        and first.isalnum()
        and 2 <= len(first) <= 7
    ):
        agent_name = first
        raw_prompt = args[1] if len(args) > 1 else None
        from assets.cli import run_agent_chat  # noqa: PLC0415
        run_agent_chat(agent_name, raw_prompt)
        return

    # Everything else goes straight to Typer
    from assets.cli import app  # noqa: PLC0415
    app()


if __name__ == "__main__":
    main()
