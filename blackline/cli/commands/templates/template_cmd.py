"""Thin CLI adapters for the shared `.bline` template registry."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
from typing import Callable

from blackline.clt.errors import CLTError, CapabilityResolutionError
from blackline.clt.runtime import CLTRuntime, CapabilityRegistry, RuntimeResult
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.cli.ui.display import error, info, result, warn, write_line, write_segments
from blackline.templates import Template, TemplateError, TemplateRegistry, TemplateStatus

EditorRunner = Callable[[list[str]], object]


def registry_for(state: ShellState) -> TemplateRegistry:
    """Return the shell-scoped registry, creating the persistent default lazily."""
    if isinstance(state.template_registry, TemplateRegistry):
        return state.template_registry
    state.template_registry = TemplateRegistry()
    return state.template_registry


def handle_load(path: str, state: ShellState, *, registry: TemplateRegistry | None = None, use_color: bool | None = None) -> bool:
    """Register a source path without executing its compiled workflow."""
    if not path.strip():
        error("load requires a template path (example: load ./web-audit.bline)", use_color=use_color)
        return False
    try:
        template = (registry or registry_for(state)).register(path.strip())
    except (TemplateError, CLTError, OSError) as exc:
        error(str(exc), use_color=use_color)
        return False
    write_segments([("[load]", "cyan"), (f" {template.name}", "white")], use_color=use_color)
    write_segments([("       source  ", "muted"), (str(template.path), "white")], use_color=use_color)
    write_segments([("       status  ", "muted"), (template.status.value, "green")], use_color=use_color)
    return True


def handle_list_templates(state: ShellState, *, registry: TemplateRegistry | None = None, use_color: bool | None = None) -> bool:
    """Render registered templates; this command owns no registry behavior."""
    templates = (registry or registry_for(state)).list()
    write_line("TEMPLATES", color="cyan", use_color=use_color)
    write_line("─────────", color="muted", use_color=use_color)
    if not templates:
        info("no templates loaded", use_color=use_color)
        return True
    width = max(len(template.name) for template in templates)
    for template in templates:
        state_label = "active" if template.name == state.active_template else template.status.value
        color = "green" if state_label in {"active", TemplateStatus.LOADED.value} else "yellow" if state_label == TemplateStatus.INVALID.value else "red"
        write_segments(
            [
                (template.name.ljust(width), "white"),
                ("  ", "muted"),
                (state_label, color),
            ],
            use_color=use_color,
        )
    return True


def handle_use(name: str, state: ShellState, *, registry: TemplateRegistry | None = None, use_color: bool | None = None) -> bool:
    """Select exactly one registered template without running it."""
    if not name.strip():
        error("use requires a registered template name", use_color=use_color)
        return False
    try:
        template = (registry or registry_for(state)).get(name, refresh=True)
    except TemplateError as exc:
        error(str(exc), use_color=use_color)
        return False
    if template.status is TemplateStatus.MISSING:
        error(template.last_error, use_color=use_color)
        return False
    state.active_template = template.name
    write_segments([("[use]", "cyan"), (f" {template.name}", "white")], use_color=use_color)
    return True


def handle_edit(
    name: str,
    state: ShellState,
    *,
    registry: TemplateRegistry | None = None,
    editor: str | None = None,
    editor_runner: EditorRunner | None = None,
    use_color: bool | None = None,
) -> bool:
    """Open a registered source, then refresh it transactionally after exit."""
    selected = name.strip() or state.active_template
    if not selected:
        error("edit requires a registered template name", use_color=use_color)
        return False
    active_registry = registry or registry_for(state)
    try:
        template = active_registry.get(selected, refresh=True)
    except TemplateError as exc:
        error(str(exc), use_color=use_color)
        return False
    if template.status is TemplateStatus.MISSING:
        error(template.last_error, use_color=use_color)
        return False
    command = editor or _editor_command()
    if not command:
        error("no editor configured; set VISUAL or EDITOR", use_color=use_color)
        return False
    before_hash = template.source_hash
    try:
        (editor_runner or _run_editor)([ *shlex.split(command), str(template.path) ])
    except (OSError, ValueError) as exc:
        error(f"could not open editor: {exc}", use_color=use_color)
        return False
    refreshed = active_registry.refresh(template.name)
    if refreshed.status is TemplateStatus.INVALID:
        warn(f"{refreshed.name} has invalid source; last valid compilation remains available", use_color=use_color)
        write_line(refreshed.last_error, color="muted", use_color=use_color)
        return False
    if refreshed.source_hash != before_hash:
        result(f"{refreshed.name} updated", use_color=use_color)
    else:
        info(f"{refreshed.name} unchanged", use_color=use_color)
    return True


def handle_run(
    expression: str,
    state: ShellState,
    *,
    registry: TemplateRegistry | None = None,
    runtime: CLTRuntime | None = None,
    use_color: bool | None = None,
) -> bool:
    """Execute an explicit or active template through the CLT runtime boundary."""
    try:
        name, inputs = parse_run_expression(expression, active_template=state.active_template)
        template = (registry or registry_for(state)).executable(name)
        run = (runtime or default_template_runtime()).run(template.compiled, variables=inputs)
    except (TemplateError, CapabilityResolutionError, ValueError) as exc:
        error(str(exc), use_color=use_color)
        return False
    if template.status is TemplateStatus.INVALID:
        warn(f"{template.name} source is invalid; ran its last valid compilation", use_color=use_color)
    _render_run(template, run, use_color=use_color)
    return True


def parse_run_expression(expression: str, *, active_template: str = "") -> tuple[str, dict[str, str]]:
    """Parse `run [name][key=value,...]` while reserving inputs for CLT later."""
    text = expression.strip()
    if not text:
        if not active_template:
            raise TemplateError("run requires a template name or an active template")
        return active_template, {}
    if text.startswith("["):
        if not active_template:
            raise TemplateError("run inputs require an active template")
        return active_template, _parse_inputs(text)
    name, bracket, tail = text.partition("[")
    if not bracket:
        return name.strip(), {}
    return name.strip(), _parse_inputs(bracket + tail)


def default_template_runtime() -> CLTRuntime:
    """Provide only non-operational CLT verbs until tool adapters are registered."""
    registry = CapabilityRegistry()
    for verb in ("analyze", "collect", "report", "save", "load"):
        registry.register(verb)
    return CLTRuntime(registry)


def _parse_inputs(text: str) -> dict[str, str]:
    if not text.endswith("]"):
        raise TemplateError("template inputs must end with ']'")
    inner = text[1:-1].strip()
    if not inner:
        return {}
    inputs: dict[str, str] = {}
    for item in inner.split(","):
        key, separator, value = item.partition("=")
        key, value = key.strip().lower(), value.strip()
        if not separator or not key or not value:
            raise TemplateError("template inputs must use key=value pairs")
        if key in inputs:
            raise TemplateError(f"duplicate template input: {key}")
        inputs[key] = value
    return inputs


def _render_run(template: Template, run: RuntimeResult, *, use_color: bool | None) -> None:
    state = "completed" if run.events else "completed with no actions"
    write_segments([("[run]", "cyan"), (f" {template.name}", "white"), (f" {state}", "green")], use_color=use_color)
    for event in run.events:
        intent = f"{event.intent.verb} {event.intent.subject}".strip()
        write_segments([("      ", "muted"), (intent, "white"), ("  done", "green")], use_color=use_color)


def _editor_command() -> str:
    return os.environ.get("VISUAL", "").strip() or os.environ.get("EDITOR", "").strip()


def _run_editor(command: list[str]) -> None:
    subprocess.run(command, check=False)
