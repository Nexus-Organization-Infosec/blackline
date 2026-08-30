"""Recon command adapter."""

from __future__ import annotations

from datetime import datetime
from difflib import get_close_matches
from pathlib import Path

from blackline.cli.commands.system.jobs_cmd import append_job_result, derive_completion_state, step_completion_state
from blackline.config.tool_loader import get_tool_config
from blackline.core.recon import InvalidReconTargetError, build_recon_pipeline
from blackline.cli.ui.display import error, result, warn, write_line
from blackline.engine.runner import normalize_expression, parse_expression, run_expression
from blackline.engine.session import EngineSession


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

    if not run.results:
        error("recon produced no results", use_color=use_color)
        return False

    last_nmap_payload: dict[str, object] = {}
    last_successful_nmap_payload: dict[str, object] = {}
    first_error = ""
    step_statuses: list[str] = []
    total_elapsed_seconds = 0.0

    for step in run.results:
        payload = step.payload if isinstance(step.payload, dict) else {}
        record_job_result(active_job, step, payload, jobs_root=jobs_root)
        step_statuses.append(
            step_completion_state(
                tool=str(getattr(step, "tool", "")),
                ok=bool(getattr(step, "ok", False)),
                payload=payload,
            )
        )
        total_elapsed_seconds += _step_elapsed_seconds(payload)
        if not first_error and getattr(step, "error", ""):
            first_error = str(getattr(step, "error", ""))

        if step.tool == "dns":
            render_dns_result(payload, ok=step.ok, step_error=step.error, use_color=use_color)
        elif step.tool == "ipintel":
            render_ipintel_result(payload, ok=step.ok, step_error=step.error, use_color=use_color)
        elif step.tool == "http":
            render_http_result(payload, ok=step.ok, step_error=step.error, use_color=use_color)
        elif step.tool == "nmap":
            render_nmap_result(payload, ok=step.ok, step_error=step.error, use_color=use_color)
            last_nmap_payload = payload
            if step.ok:
                last_successful_nmap_payload = payload

    completion_state = derive_completion_state(step_statuses)
    if run.cancelled:
        warn(run.cancellation_reason or "recon cancelled by user", use_color=use_color)
        if active_job:
            append_job_result(
                active_job,
                {
                    "recorded_at": datetime.now().isoformat(timespec="seconds"),
                    "module": "recon",
                    "tool": "recon",
                    "action": "cancelled",
                    "ok": False,
                    "error": run.cancellation_reason or "recon cancelled by user",
                    "summary": {"cancelled": True},
                    "payload": {"warnings": [], "elapsed_seconds": 0.0},
                },
                jobs_root=jobs_root,
            )
        completion_state = "partial" if step_statuses else "failed"

    if completion_state == "failed":
        error(first_error or run.cancellation_reason or "recon failed", use_color=use_color)
        return False

    if last_nmap_payload or step_statuses:
        render_recon_summary(
            completion_state,
            nmap_payload=last_successful_nmap_payload,
            active_job=active_job,
            elapsed_seconds=total_elapsed_seconds,
            use_color=use_color,
        )
        return True

    error(first_error or "recon failed", use_color=use_color)
    return False


def validate_recon_expression(expression: str) -> str:
    """Validate recon input before execution."""
    context = parse_expression(expression)
    arguments = recon_argument_names()

    if not arguments:
        return "recon configuration unavailable"

    for key in context.params:
        if key not in arguments:
            suggestion = closest_argument(key, arguments)
            if suggestion:
                return f"unknown recon argument: {key} (did you mean {suggestion}?)"
            return f"unknown recon argument: {key}"

    if not context.params.get("target"):
        return "missing required recon argument: target"

    try:
        build_recon_pipeline(context.params["target"])
    except InvalidReconTargetError as exc:
        return str(exc)

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


def render_dns_result(payload: dict, *, ok: bool, step_error: str, use_color: bool | None = None) -> None:
    """Render a concise DNS section."""
    write_line("[dns]", use_color=use_color)
    records = payload.get("records", {})
    if not isinstance(records, dict):
        records = {}

    rendered = False
    for record_type in ("A", "AAAA", "MX", "NS"):
        values = records.get(record_type, [])
        if not isinstance(values, list):
            values = []
        text = ", ".join(str(value) for value in values) if values else "none"
        write_line(f"{record_type.ljust(6)} {text}", use_color=use_color)
        rendered = True

    if not rendered and step_error:
        write_line(step_error, use_color=use_color)
    elif not ok and step_error:
        write_line(step_error, use_color=use_color)
    write_line(use_color=use_color)


def render_nmap_result(
    payload: dict,
    *,
    ok: bool,
    step_error: str,
    use_color: bool | None = None,
) -> None:
    """Render native nmap output."""
    command = " ".join(payload.get("command", []))
    if command:
        write_line(command, use_color=use_color)
        write_line(use_color=use_color)

    raw_output = str(payload.get("raw_output") or "").strip()
    if raw_output:
        for line in raw_output.splitlines():
            write_line(line, use_color=use_color)
    elif ok:
        render_ports_table(payload.get("ports", []), use_color=use_color)
    elif step_error:
        error(step_error, use_color=use_color)


def render_http_result(payload: dict, *, ok: bool, step_error: str, use_color: bool | None = None) -> None:
    """Render a concise HTTP probe section."""
    write_line("[http]", use_color=use_color)
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    rendered = False
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        url = str(finding.get("url", "")).strip() or "unknown"
        status_code = finding.get("status_code")
        if isinstance(status_code, int):
            line = f"{url.ljust(24)} {status_code}"
            title = str(finding.get("title", "")).strip()
            redirect_to = str(finding.get("redirect_to", "")).strip()
            if title:
                line = f"{line}   {title}"
            if redirect_to:
                line = f"{line}   -> {redirect_to}"
        else:
            error_text = str(finding.get("error", "")).strip() or "failed"
            line = f"{url.ljust(24)} {error_text}"
        write_line(line, use_color=use_color)
        rendered = True

    if not rendered and step_error:
        write_line(step_error, use_color=use_color)
    elif not ok and step_error:
        write_line(step_error, use_color=use_color)
    write_line(use_color=use_color)


def render_ipintel_result(payload: dict, *, ok: bool, step_error: str, use_color: bool | None = None) -> None:
    """Render a concise IP intelligence section."""
    write_line("[ipintel]", use_color=use_color)
    write_line(use_color=use_color)
    write_line("network", color="cyan", use_color=use_color)
    write_line("───────", color="muted", use_color=use_color)

    asn = str(payload.get("asn", "")).strip()
    org = str(payload.get("org", "")).strip()
    asn_text = " ".join(part for part in (asn, org) if part).strip() or "none"
    write_line(f"asn       : {asn_text}", use_color=use_color)

    location = str(payload.get("location", "")).strip() or "unknown"
    write_line(f"location  : {location}", use_color=use_color)

    latency = payload.get("latency")
    latency_text = f"~{float(latency):.1f} ms" if isinstance(latency, (int, float)) else "unknown"
    write_line(f"latency   : {latency_text}", use_color=use_color)

    if isinstance(payload.get("jitter"), (int, float)):
        write_line(f"jitter    : {float(payload['jitter']):.1f} ms", use_color=use_color)
    if isinstance(payload.get("bandwidth"), (int, float)):
        write_line(f"bandwidth : ~{float(payload['bandwidth']):.2f} Mbps", use_color=use_color)

    write_line(use_color=use_color)
    write_line("[anonymity]", use_color=use_color)
    vpn_likely = payload.get("vpn_likely")
    if isinstance(vpn_likely, bool):
        vpn_text = "likely" if vpn_likely else "unlikely"
    else:
        vpn_text = "unknown"
    write_line(f"vpn       : {vpn_text}", use_color=use_color)
    confidence = str(payload.get("confidence", "")).strip() or "unknown"
    write_line(f"confidence: {confidence}", use_color=use_color)
    if not ok and step_error:
        write_line(step_error, use_color=use_color)
    write_line(use_color=use_color)


def render_recon_summary(
    completion_state: str,
    *,
    nmap_payload: dict[str, object] | None = None,
    active_job: str = "",
    elapsed_seconds: float = 0.0,
    use_color: bool | None = None,
) -> None:
    """Render the final recon summary line."""
    nmap_payload = nmap_payload or {}
    summary = _recon_summary_text(completion_state, nmap_payload)
    if elapsed_seconds > 0:
        summary = f"{summary} ({format_elapsed(elapsed_seconds)})"
    if active_job:
        summary = f"{summary} -> #{active_job}"
    result(summary, use_color=use_color)


def _recon_summary_text(completion_state: str, payload: dict[str, object]) -> str:
    """Return the final recon summary text for one run."""
    ports = payload.get("ports", [])
    if not isinstance(ports, list):
        ports = []
    open_count = payload.get("open_ports")
    filtered_count = payload.get("filtered_ports")
    interesting_count = payload.get("interesting_ports")
    if not isinstance(open_count, int):
        open_count = len([port for port in ports if str(port.get("state", "")).lower() == "open"])
    if not isinstance(filtered_count, int):
        filtered_count = len([port for port in ports if str(port.get("state", "")).lower() == "filtered"])
    if not isinstance(interesting_count, int):
        interesting_count = open_count + filtered_count

    if payload:
        findings = _port_scan_summary_text(open_count, filtered_count, interesting_count)
        if completion_state == "completed":
            return findings
        if completion_state == "completed_with_warnings":
            return f"{findings} with warnings"
        if completion_state == "partial":
            return f"{findings}, partial"

    if completion_state == "completed_with_warnings":
        return "recon complete with warnings"
    if completion_state == "partial":
        return "recon partial"
    return "recon complete"


def render_ports_table(ports: list[dict[str, object]], *, use_color: bool | None = None) -> None:
    """Render a native-looking port table when raw tool output is unavailable."""
    interesting_ports = [
        port for port in ports if str(port.get("state", "")).lower() in {"open", "filtered"}
    ]
    if not interesting_ports:
        write_line("No open ports found.", use_color=use_color)
        return

    labels = [f"{port.get('port', '')}/{port.get('protocol', '')}" for port in interesting_ports]
    width = max(len("PORT"), *(len(label) for label in labels))
    write_line(f"{'PORT'.ljust(width)}  STATE SERVICE", use_color=use_color)
    for port, label in zip(interesting_ports, labels):
        state = str(port.get("state", "")).ljust(8)
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

    if getattr(step, "tool", "") == "dns":
        records = payload.get("records", {})
        if not isinstance(records, dict):
            records = {}
        entry = {
            "recorded_at": datetime.now().isoformat(timespec="seconds"),
            "module": "recon",
            "tool": getattr(step, "tool", ""),
            "action": getattr(step, "action", ""),
            "ok": bool(getattr(step, "ok", False)),
            "error": str(getattr(step, "error", "")),
            "summary": {
                "target": payload.get("target", ""),
                "resolved_ips": list(payload.get("resolved_ips", [])) if isinstance(payload.get("resolved_ips", []), list) else [],
                "record_count": sum(len(values) for values in records.values() if isinstance(values, list)),
                "elapsed_seconds": payload.get("elapsed_seconds"),
            },
            "payload": payload,
        }
        append_job_result(active_job, entry, jobs_root=jobs_root)
        return

    if getattr(step, "tool", "") == "ipintel":
        entry = {
            "recorded_at": datetime.now().isoformat(timespec="seconds"),
            "module": "recon",
            "tool": getattr(step, "tool", ""),
            "action": getattr(step, "action", ""),
            "ok": bool(getattr(step, "ok", False)),
            "error": str(getattr(step, "error", "")),
            "summary": {
                "target": payload.get("target", ""),
                "lookup_ip": payload.get("lookup_ip", ""),
                "asn": payload.get("asn", ""),
                "location": payload.get("location", ""),
                "elapsed_seconds": payload.get("elapsed_seconds"),
            },
            "payload": payload,
        }
        append_job_result(active_job, entry, jobs_root=jobs_root)
        return

    if getattr(step, "tool", "") == "http":
        findings = payload.get("findings", [])
        if not isinstance(findings, list):
            findings = []
        entry = {
            "recorded_at": datetime.now().isoformat(timespec="seconds"),
            "module": "recon",
            "tool": getattr(step, "tool", ""),
            "action": getattr(step, "action", ""),
            "ok": bool(getattr(step, "ok", False)),
            "error": str(getattr(step, "error", "")),
            "summary": {
                "target": payload.get("target", ""),
                "mode": payload.get("mode", ""),
                "findings": len(findings),
                "elapsed_seconds": payload.get("elapsed_seconds"),
            },
            "payload": payload,
        }
        append_job_result(active_job, entry, jobs_root=jobs_root)
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
            "open_ports": payload.get("open_ports", len([port for port in ports if str(port.get("state", "")).lower() == "open"])),
            "filtered_ports": payload.get("filtered_ports", len([port for port in ports if str(port.get("state", "")).lower() == "filtered"])),
            "interesting_ports": payload.get("interesting_ports"),
            "elapsed_seconds": payload.get("elapsed_seconds"),
        },
        "payload": payload,
    }
    append_job_result(active_job, entry, jobs_root=jobs_root)


def _port_scan_summary_text(open_count: int, filtered_count: int, interesting_count: int) -> str:
    if open_count and filtered_count:
        return f"{open_count} open, {filtered_count} filtered"
    if open_count:
        return f"{open_count} open ports"
    if filtered_count:
        return f"{filtered_count} filtered ports"
    if interesting_count:
        return f"{interesting_count} interesting ports"
    return "0 open ports"


def _step_elapsed_seconds(payload: dict[str, object]) -> float:
    """Return the step elapsed time when present."""
    elapsed = payload.get("elapsed_seconds")
    if isinstance(elapsed, (int, float)) and elapsed > 0:
        return float(elapsed)
    return 0.0
