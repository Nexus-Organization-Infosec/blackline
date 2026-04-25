"""Interactive shell core."""

from __future__ import annotations

try:
    import readline
except ImportError:  # pragma: no cover - readline is Unix-only.
    readline = None  # type: ignore[assignment]

from blackline.cli.commands.system.help_cmd import handle_help
from blackline.cli.commands.system.jobs_cmd import (
    handle_delete_job,
    handle_enter,
    handle_jobs,
    handle_leave_job,
    handle_new,
    handle_show,
)
from blackline.cli.commands.tools.recon_cmd import handle_recon, validate_recon_expression
from blackline.cli.commands.tools.network_cmd import handle_network
from blackline.cli.commands.utils.shell_cmds import (
    ShellState,
    handle_clear,
    handle_history,
    handle_history_clear,
    handle_placeholder,
    handle_reset,
    record_history,
    handle_version,
)
from blackline.cli.ui.display import error, result
from blackline.cli.ui.elements import prompt_line
from blackline.cli.ui.live_input import create_prompt_session, prompt_fragments
from blackline.utils.tab_complete import ReadlineCompleter

PLANNED_COMMANDS = {"run", "use", "load", "list", "edit", "update"}
_COMPLETER: ReadlineCompleter | None = None


def run_shell() -> int:
    """Run a minimal interactive shell."""
    state = ShellState()
    session = create_prompt_session()
    if session is None:
        configure_tab_completion()
    while True:
        try:
            if session is None:
                line = input(prompt_line(state.active_job)).strip()
            else:
                line = session.prompt(prompt_fragments(state.active_job)).strip()
        except KeyboardInterrupt:
            print()
            continue
        except EOFError:
            print()
            return 0

        if not line:
            continue

        if execute_shell_line(line, state):
            return 0


def execute_shell_line(line: str, state: ShellState | None = None) -> bool:
    """Run one interactive shell line with command-result spacing."""
    if not line.strip():
        return False

    print()
    should_exit = dispatch_line(line, state)
    print()
    return should_exit


def configure_tab_completion() -> None:
    """Enable readline tab completion for the interactive shell."""
    if readline is None:
        return

    global _COMPLETER
    completer = ReadlineCompleter()
    _COMPLETER = completer
    readline.set_completer(completer.complete)
    if "libedit" in (readline.__doc__ or ""):
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")


def dispatch_line(line: str, state: ShellState | None = None) -> bool:
    """Dispatch one shell input line. Returns True when shell should exit."""
    state = state or ShellState()
    stripped = line.strip()
    command = stripped.lower()
    name = command.split(maxsplit=1)[0] if command else ""

    if command:
        record_history(state, stripped)

    if command == "exit" and handle_leave_job(state):
        return False

    if command in {"exit", "quit"}:
        result("bye.")
        return True

    if command == "clear":
        handle_clear()
        return False

    if command == "version":
        handle_version()
        return False

    if command == "history all":
        handle_history(state, show_all=True)
        return False

    if command == "history clear":
        handle_history_clear(state)
        return False

    if command == "history":
        handle_history(state)
        return False

    if command == "reset":
        handle_reset(state)
        return False

    if command == "new" or command.startswith("new "):
        handle_new(stripped.removeprefix("new").strip(), state)
        return False

    if command == "show":
        handle_show(state)
        return False

    if command.startswith("show "):
        handle_show(state, stripped.split(maxsplit=1)[1])
        return False

    if command == "jobs":
        handle_jobs()
        return False

    if command.startswith("enter "):
        handle_enter(stripped.split(maxsplit=1)[1], state)
        return False

    if command.startswith("delete "):
        handle_delete_job(stripped.split(maxsplit=1)[1], state)
        return False

    if command == "network":
        handle_network()
        return False

    if is_recon_command(stripped):
        maybe_enter_tool_job(stripped, state)
        handle_recon(stripped, active_job=state.active_job)
        return False

    if command == "help" or command.startswith("help "):
        handle_help(command.removeprefix("help").strip())
        return False

    if name in PLANNED_COMMANDS:
        handle_placeholder(name)
        return False

    error(f"unknown command: {line}")
    return False


def is_recon_command(text: str) -> bool:
    """Return True when text targets the recon command, spaced or compact."""
    stripped = text.strip()
    return stripped.lower() == "recon" or stripped.lower().startswith("recon[") or stripped.lower().startswith("recon [")


def maybe_enter_tool_job(expression: str, state: ShellState) -> bool:
    """Auto-create and enter a job for tool execution from the global shell."""
    if state.active_job:
        return False
    if validate_recon_expression(expression):
        return False
    return handle_new(expression, state, render_summary=False)
