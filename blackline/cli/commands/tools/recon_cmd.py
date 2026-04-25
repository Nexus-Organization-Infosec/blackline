"""Recon command adapter."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from difflib import get_close_matches

from blackline.cli.commands.system.jobs_cmd import append_job_result
from blackline.config.tool_loader import get_tool_config
from blackline.cli.ui.display import error, result, write_line
from blackline.engine.runner import normalize_expression, parse_expression, run_expression
from blackline.engine.state.session import EngineSession


def handle_recon(
    expression: str,
    *,
    active_job: str = "",
    jobs_root: Path | None = None,
    use_color: bool | None = None,
) -> bool:
    """Run a recon expression through the engine and render results."""
    expression = normalize_expression(expression)
    validation_error = validate_recon_expression(expression)
    if validation_error:
        error(validation_error, use_color=use_color)
        return False

    run = run_expression(expression, session=EngineSession(active_job=active_job))
    if not run.plan.steps:
        error("recon plan is empty", use_color=use_color)
        return False

    step = run.results[0]
    payload = step.payload
    command = " ".join(payload.get("command", []))
    if command:
        write_line(command, use_color=use_color)
        write_line(use_color=use_color)

    record_job_result(active_job, step, payload, jobs_root=jobs_root)
    if not step.ok:
        error(step.error or "recon failed", use_color=use_color)
        return False

    ports = payload.get("ports", [])
    if not isinstance(ports, list):
        ports = []
    open_ports = [port for port in ports if str(port.get("state", "")).lower() == "open"]
    elapsed_seconds = payload.get("elapsed_seconds")
    raw_output = str(payload.get("raw_output") or "").strip()
    if raw_output:
        for line in raw_output.splitlines():
            write_line(line, use_color=use_color)
    else:
        render_ports_table(payload.get("ports", []), use_color=use_color)

    summary = f"{len(open_ports)} open ports"
    if isinstance(elapsed_seconds, (int, float)) and elapsed_seconds > 0:
        summary = f"{summary} ({format_elapsed(elapsed_seconds)})"
    if active_job:
        summary = f"{summary} -> #{active_job}"
    result(summary, use_color=use_color)
    return True


def validate_recon_expression(expression: str) -> str:
    """Validate recon input before execution."""
    context = parse_expression(expression)
    arguments = recon_argument_names()

    for key in context.params:
        if key not in arguments:
            suggestion = closest_argument(key, arguments)
            if suggestion:
                return f"unknown recon argument: {key} (did you mean {suggestion}?)"
            return f"unknown recon argument: {key}"

    if not context.params.get("target"):
        return "missing required recon argument: target"

    return ""


def recon_argument_names() -> set[str]:
    """Return supported recon argument names from config."""
    config = get_tool_config("recon")
    arguments = config.get("arguments", {})
    if not isinstance(arguments, dict):
        return set()
    return {str(key) for key in arguments}


def closest_argument(argument: str, arguments: set[str]) -> str:
    """Return the closest configured argument name."""
    matches = get_close_matches(argument, sorted(arguments), n=1, cutoff=0.6)
    return matches[0] if matches else ""


def format_elapsed(seconds: float) -> str:
    """Format elapsed wall-clock seconds for display."""
    if seconds >= 60:
        minutes = int(seconds // 60)
        remainder = seconds - (minutes * 60)
        return f"{minutes}m {remainder:.1f}s"
    return f"{seconds:.1f}s"


def render_ports_table(ports: list[dict[str, object]], *, use_color: bool | None = None) -> None:
    """Render a native-looking port table when raw tool output is unavailable."""
    open_ports = [port for port in ports if str(port.get("state", "")).lower() == "open"]
    if not open_ports:
        write_line("No open ports found.", use_color=use_color)
        return

    labels = [f"{port.get('port', '')}/{port.get('protocol', '')}" for port in open_ports]
    width = max(len("PORT"), *(len(label) for label in labels))
    write_line(f"{'PORT'.ljust(width)}  STATE SERVICE", use_color=use_color)
    for port, label in zip(open_ports, labels):
        state = str(port.get("state", "")).ljust(5)
        service = str(port.get("service", ""))
        write_line(f"{label.ljust(width)}  {state} {service}".rstrip(), use_color=use_color)


def record_job_result(
    active_job: str,
    step: object,
    payload: dict,
    *,
    jobs_root: Path | None = None,
) -> None:
    """Persist one structured recon result into the active job."""
    if not active_job:
        return

    ports = payload.get("ports", [])
    if not isinstance(ports, list):
        ports = []
    entry = {
        "recorded_at": datetime.now().isoformat(timespec="seconds"),
        "module": "recon",
        "tool": getattr(step, "tool", ""),
        "action": getattr(step, "action", ""),
        "ok": bool(getattr(step, "ok", False)),
        "error": str(getattr(step, "error", "")),
        "summary": {
            "target": payload.get("target", ""),
            "host_status": payload.get("host_status", ""),
            "open_ports": len([port for port in ports if str(port.get("state", "")).lower() == "open"]),
            "elapsed_seconds": payload.get("elapsed_seconds"),
        },
        "payload": payload,
    }
    append_job_result(active_job, entry, jobs_root=jobs_root)
