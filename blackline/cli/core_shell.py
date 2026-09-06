"""Interactive shell core."""

from __future__ import annotations

try:
    import readline
except ImportError:  # pragma: no cover - readline is Unix-only.
    readline = None  # type: ignore[assignment]

from blackline.cli.auth import close_elevated_session, is_elevated, refresh_sudo_state
from blackline.cli.commands.system.jobs_cmd import handle_leave_job
from blackline.cli.commands.utils.shell_cmds import (
    ShellState,
    record_history,
)
from blackline.cli.dispatcher import dispatch_command, is_recon_command
from blackline.cli.ui.display import info, write_segments
from blackline.cli.ui.elements import prompt_line
from blackline.cli.ui.live_input import create_prompt_session, prompt_fragments
from blackline.utils.tab_complete import ReadlineCompleter

_COMPLETER: ReadlineCompleter | None = None


def run_shell() -> int:
    """Run a minimal interactive shell."""
    state = ShellState()
    session = create_prompt_session()
    state.prompt_session = session
    if session is None:
        configure_tab_completion()
    while True:
        try:
            refresh_sudo_state(state)
            if session is None:
                line = input(prompt_line(state.active_job, active_template=state.active_template, elevated=is_elevated(state))).strip()
            else:
                line = session.prompt(prompt_fragments(state.active_job, active_template=state.active_template, elevated=is_elevated(state))).strip()
        except KeyboardInterrupt:
            print()
            continue
        except EOFError:
            print()
            if unwind_current_context(state):
                return 0
            continue

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
    if stripped:
        record_history(state, stripped)
    outcome = dispatch_command(
        stripped,
        state,
        exit_context=unwind_current_context,
        manage_elevation=True,
    )
    return outcome.exit_shell


def unwind_current_context(state: ShellState, *, use_color: bool | None = None) -> bool:
    """Leave one shell context layer at a time."""
    if close_elevated_session(state, use_color=use_color):
        return False
    if handle_leave_job(state, use_color=use_color):
        return False
    if state.active_template:
        template = state.active_template
        state.active_template = ""
        info(f"left template {template}", use_color=use_color)
        return False
    write_segments([("[shutdown]", "muted"), (" session terminated", "white")], use_color=use_color)
    return True
