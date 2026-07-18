"""
StelarStrike entry point.

Handles the special `stelarstrike <agent> "<prompt>"` format:
if the first argument is not a known Typer command and not a flag,
it is treated as an agent name and the second argument as the prompt.
Everything else routes normally through the Typer app.
"""

from __future__ import annotations

import sys

# Commands registered in cli.py (all Typer command names + flag-style names)
_KNOWN_COMMANDS = {
    "scan", "plugins", "schemas", "doctor", "version",
    "--createagent", "--deleteagent", "--agents",
    "--skills", "--tools", "--version", "--help", "-h",
}


def main() -> None:
    args = sys.argv[1:]

    # Detect `stelarstrike <agent> "<prompt>"` pattern:
    # - First arg is not a flag and not a known command
    # - First arg looks like an agent name (alphanumeric, 2-7 chars)
    if (
        args
        and not args[0].startswith("-")
        and args[0] not in _KNOWN_COMMANDS
        and args[0].isalnum()
        and 2 <= len(args[0]) <= 7
    ):
        agent_name = args[0]
        # Prompt is the second argument (must be quoted by the shell — arrives as one string)
        raw_prompt = args[1] if len(args) > 1 else None
        from stelarstrike.cli import run_agent_chat  # noqa: PLC0415
        run_agent_chat(agent_name, raw_prompt)
        return

    from stelarstrike.cli import app  # noqa: PLC0415
    app()


if __name__ == "__main__":
    main()
