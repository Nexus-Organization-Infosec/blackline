"""CLI entrypoint."""

from __future__ import annotations

import argparse
import sys

from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.cli.core_shell import run_shell
from blackline.cli.dispatcher import dispatch_command
from blackline.cli.ui.elements import render_startup, run_startup_checks


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
        state = ShellState()
        outcome = dispatch_command(args.command, state, render_unknown=False)
        return outcome.exit_code

    if sys.stdin.isatty():
        print()
        return run_shell()

    return 0
if __name__ == "__main__":
    raise SystemExit(main())
