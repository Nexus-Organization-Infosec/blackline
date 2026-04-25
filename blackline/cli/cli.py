"""CLI entrypoint."""

from __future__ import annotations

import argparse
import sys

from blackline.cli.commands.system.help_cmd import handle_help
from blackline.cli.commands.system.jobs_cmd import handle_delete_job, handle_enter, handle_jobs, handle_new, handle_show
from blackline.cli.commands.tools.recon_cmd import handle_recon
from blackline.cli.commands.tools.network_cmd import handle_network
from blackline.cli.commands.utils.shell_cmds import (
    ShellState,
    handle_clear,
    handle_history,
    handle_history_clear,
    handle_placeholder,
    handle_reset,
    handle_version,
)
from blackline.cli.core_shell import run_shell
from blackline.cli.ui.elements import render_startup, run_startup_checks

PLANNED_COMMANDS = {"run", "use", "load", "list", "edit", "update"}


def main(argv: list[str] | None = None) -> int:
    """Run Blackline."""
    parser = argparse.ArgumentParser(prog="blackline")
    parser.add_argument("--command", "-c", help="run one command and exit")
    args = parser.parse_args(argv)

    results = run_startup_checks()
    render_startup(results)
    if not all(result.ok for result in results):
        return 1

    if args.command:
        command = args.command.strip().lower()
        name = command.split(maxsplit=1)[0] if command else ""
        if command == "network":
            handle_network()
            return 0
        if is_recon_command(args.command.strip()):
            handle_recon(args.command.strip())
            return 0
        if command == "clear":
            handle_clear()
            return 0
        if command == "version":
            handle_version()
            return 0
        if command == "history all":
            handle_history(ShellState(), show_all=True)
            return 0
        if command == "history clear":
            handle_history_clear(ShellState())
            return 0
        if command == "history":
            handle_history(ShellState())
            return 0
        if command == "reset":
            handle_reset(ShellState())
            return 0
        if command == "new" or command.startswith("new "):
            handle_new(args.command.strip().removeprefix("new").strip(), ShellState())
            return 0
        if command == "show":
            handle_show(ShellState())
            return 0
        if command.startswith("show "):
            handle_show(ShellState(), args.command.strip().split(maxsplit=1)[1])
            return 0
        if command == "jobs":
            handle_jobs()
            return 0
        if command.startswith("enter "):
            handle_enter(args.command.strip().split(maxsplit=1)[1], ShellState())
            return 0
        if command.startswith("delete "):
            handle_delete_job(args.command.strip().split(maxsplit=1)[1], ShellState())
            return 0
        if command == "help" or command.startswith("help "):
            handle_help(command.removeprefix("help").strip())
            return 0
        if name in PLANNED_COMMANDS:
            handle_placeholder(name)
            return 0
        return 2

    if sys.stdin.isatty():
        print()
        return run_shell()

    return 0


def is_recon_command(text: str) -> bool:
    """Return True when text targets the recon command, spaced or compact."""
    stripped = text.strip()
    return stripped.lower() == "recon" or stripped.lower().startswith("recon[") or stripped.lower().startswith("recon [")


if __name__ == "__main__":
    raise SystemExit(main())
