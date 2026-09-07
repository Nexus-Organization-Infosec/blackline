"""Shared command recognition and dispatch for Blackline CLI surfaces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from blackline.cli.auth import ensure_elevated_session
from blackline.cli.commands.network.network_cmd import handle_network
from blackline.cli.commands.recon.recon_cmd import handle_recon, validate_recon_expression
from blackline.cli.commands.system.help_cmd import handle_help
from blackline.cli.commands.system.jobs_cmd import handle_delete_job, handle_enter, handle_jobs, handle_new, handle_show
from blackline.cli.commands.templates.template_cmd import handle_edit, handle_list_templates, handle_load, handle_run, handle_use
from blackline.cli.commands.utils.tool_install_cmd import handle_install
from blackline.cli.commands.utils.shell_cmds import (
    ShellState,
    handle_clear,
    handle_history,
    handle_history_clear,
    handle_placeholder,
    handle_reset,
    handle_version,
)
from blackline.cli.ui.display import error
from blackline.core.recon.privileges import requires_elevation

PLANNED_COMMANDS = {"update"}


@dataclass(frozen=True, slots=True)
class ParsedCommand:
    """Normalized command envelope while preserving command-specific source."""

    raw: str
    name: str
    argument: str


@dataclass(frozen=True, slots=True)
class DispatchResult:
    """Outcome shared by one-shot and interactive command execution."""

    exit_code: int = 0
    exit_shell: bool = False


def parse_command(line: str) -> ParsedCommand:
    """Split normal command input once without parsing specialized grammars."""
    raw = line.strip()
    if not raw:
        return ParsedCommand(raw="", name="", argument="")
    if is_recon_command(raw):
        return ParsedCommand(raw=raw, name="recon", argument=raw)

    name, separator, argument = raw.partition(" ")
    if not separator:
        return ParsedCommand(raw=raw, name=name.lower(), argument="")
    return ParsedCommand(raw=raw, name=name.lower(), argument=argument.strip())


def is_recon_command(text: str) -> bool:
    """Return True when text targets recon's independent expression grammar."""
    stripped = text.strip().lower()
    return stripped == "recon" or stripped.startswith("recon[") or stripped.startswith("recon [")


def dispatch_command(
    line: str,
    state: ShellState,
    *,
    exit_context: Callable[[ShellState], bool] | None = None,
    manage_elevation: bool = False,
    render_unknown: bool = True,
) -> DispatchResult:
    """Dispatch one command through the shared explicit routing table."""
    command = parse_command(line)
    if not command.name:
        return DispatchResult()

    if command.name in {"exit", "quit"} and not command.argument:
        return DispatchResult(exit_shell=exit_context(state) if exit_context else True)

    if command.name == "clear" and not command.argument:
        handle_clear()
        return DispatchResult()
    if command.name == "version" and not command.argument:
        handle_version()
        return DispatchResult()
    if command.name == "history":
        if command.argument.lower() == "all":
            handle_history(state, show_all=True)
            return DispatchResult()
        if command.argument.lower() == "clear":
            handle_history_clear(state)
            return DispatchResult()
        if not command.argument:
            handle_history(state)
            return DispatchResult()
    if command.name == "reset" and not command.argument:
        handle_reset(state)
        return DispatchResult()
    if command.name == "new":
        handle_new(command.argument, state)
        return DispatchResult()
    if command.name == "show":
        handle_show(state, command.argument) if command.argument else handle_show(state)
        return DispatchResult()
    if command.name == "jobs" and not command.argument:
        handle_jobs()
        return DispatchResult()
    if command.name == "enter" and command.argument:
        handle_enter(command.argument, state)
        return DispatchResult()
    if command.name == "delete" and command.argument:
        handle_delete_job(command.argument, state)
        return DispatchResult()
    if command.name == "network" and not command.argument:
        handle_network()
        return DispatchResult()
    if command.name == "list" and command.argument.lower() in {"", "templates"}:
        return DispatchResult(exit_code=0 if handle_list_templates(state) else 1)
    if command.name == "load":
        return DispatchResult(exit_code=0 if handle_load(command.argument, state) else 1)
    if command.name == "install":
        return DispatchResult(exit_code=0 if handle_install(command.argument) else 1)
    if command.name == "use":
        return DispatchResult(exit_code=0 if handle_use(command.argument, state) else 1)
    if command.name == "edit":
        return DispatchResult(exit_code=0 if handle_edit(command.argument, state) else 1)
    if command.name == "run":
        return DispatchResult(exit_code=0 if handle_run(command.argument, state) else 1)
    if command.name == "recon":
        return _dispatch_recon(command.raw, state, manage_elevation=manage_elevation)
    if command.name == "help":
        handle_help(command.argument.lower())
        return DispatchResult()
    if command.name in PLANNED_COMMANDS:
        handle_placeholder(command.name)
        return DispatchResult()

    if render_unknown:
        error(f"unknown command: {command.raw}")
    return DispatchResult(exit_code=2)


def _dispatch_recon(expression: str, state: ShellState, *, manage_elevation: bool) -> DispatchResult:
    """Run recon while keeping its grammar and privilege rules outside parsing."""
    validation_error = validate_recon_expression(expression)
    if not validation_error and manage_elevation and requires_elevation(expression) and not ensure_elevated_session(state):
        return DispatchResult(exit_code=1)
    if not validation_error and not state.active_job:
        handle_new(expression, state, render_summary=False)
    handle_recon(expression, active_job=state.active_job)
    return DispatchResult(exit_code=1 if validation_error else 0)
