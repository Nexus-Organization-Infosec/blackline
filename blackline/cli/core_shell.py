"""Interactive shell core."""

from __future__ import annotations

try:
    import readline
except ImportError:  # pragma: no cover - readline is Unix-only.
    readline = None  # type: ignore[assignment]

from blackline.cli.auth import close_elevated_session, ensure_elevated_session, is_elevated, refresh_sudo_state
from blackline.cli.commands.system.help_cmd import handle_help
from blackline.cli.commands.system.jobs_cmd import (
    handle_delete_job,
    handle_enter,
    handle_jobs,
    handle_leave_job,
    handle_new,
    handle_show,
)
from blackline.cli.commands.recon.recon_cmd import handle_recon, validate_recon_expression
from blackline.cli.commands.network.network_cmd import handle_network
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
from blackline.cli.ui.display import error, result, write_segments
from blackline.cli.ui.elements import prompt_line
from blackline.cli.ui.live_input import create_prompt_session, prompt_fragments
from blackline.engine.planner import PlanStep, build_plan
from blackline.engine.runner import parse_expression
from blackline.tools.network.nmap import NmapRequest, requires_sudo_for_request
from blackline.utils.tab_complete import ReadlineCompleter

PLANNED_COMMANDS = {"run", "use", "load", "list", "edit", "update"}
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
                line = input(prompt_line(state.active_job, elevated=is_elevated(state))).strip()
            else:
                line = session.prompt(prompt_fragments(state.active_job, elevated=is_elevated(state))).strip()
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
    command = stripped.lower()
    name = command.split(maxsplit=1)[0] if command else ""

    if command:
        record_history(state, stripped)

    if command in {"exit", "quit"}:
        return unwind_current_context(state)

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
        if _recon_requires_elevation(stripped):
            if not ensure_elevated_session(state):
                return False
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


def unwind_current_context(state: ShellState, *, use_color: bool | None = None) -> bool:
    """Leave one shell context layer at a time."""
    if close_elevated_session(state, use_color=use_color):
        return False
    if handle_leave_job(state, use_color=use_color):
        return False
    write_segments([("[shutdown]", "muted"), (" session terminated", "white")], use_color=use_color)
    return True


def _recon_requires_elevation(expression: str) -> bool:
    """Return True when recon planning includes a privileged nmap request."""
    if validate_recon_expression(expression):
        return False

    context = parse_expression(expression)
    plan = build_plan(context)
    for step in plan.steps:
        if step.tool != "nmap":
            continue
        request = _nmap_request_from_step(step)
        if requires_sudo_for_request(request):
            return True
    return False


def _nmap_request_from_step(step: PlanStep) -> NmapRequest:
    """Build an nmap request from one planned nmap step."""
    return NmapRequest(
        target=str(step.params.get("target", "")),
        ports=str(step.params.get("ports", "")),
        top_ports=str(step.params.get("top_ports", "")),
        profile=str(step.params.get("profile", "default") or "default"),
        timing=str(step.params.get("timing", "")),
        service_detection=_truthy(step.params.get("service_detection", "")),
        scripts=_truthy(step.params.get("scripts", "")),
        os_detection=_truthy(step.params.get("os_detection", "")),
    )


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
