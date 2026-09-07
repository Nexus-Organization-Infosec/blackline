"""Recon command adapter."""

from __future__ import annotations

from datetime import datetime
from difflib import get_close_matches
from pathlib import Path
import sys
from urllib.parse import urlsplit

from blackline.cli.commands.system.jobs_cmd import append_job_result, derive_completion_state, step_completion_state
from blackline.cli.ui.colors import colorize
from blackline.config.tool_loader import get_tool_config
from blackline.core.recon import InvalidReconTargetError, build_evidence_graph, build_recon_pipeline
from blackline.core.recon.outcomes import classify_result
from blackline.cli.ui.display import error, result, warn, write_line, write_segments
from blackline.engine.runner import normalize_expression, parse_expression, run_expression
from blackline.engine.executor import ExecutionProgress
from blackline.engine.planner import ExecutionPlan, PlanStep
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

    progress = ReconProgressRenderer(use_color=use_color)
    run = run_expression(
        expression,
        session=EngineSession(active_job=active_job),
        plan_callback=progress.show_plan,
        progress_callback=progress.update,
        vector_callback=lambda investigation_round: render_vector_round(investigation_round, use_color=use_color),
    )
    progress.finish(cancelled=run.cancelled)
    if not run.plan.steps:
        error("recon plan is empty", use_color=use_color)
        return False

    if not run.results:
        error("recon produced no results", use_color=use_color)
        return False

    last_nmap_payload: dict[str, object] = {}
    last_successful_nmap_payload: dict[str, object] = {}
    report_payloads: dict[str, dict] = {}
    first_error = ""
    step_statuses: list[str] = []
    total_elapsed_seconds = 0.0

    render_recon_context(run.context.params, use_color=use_color)

    for step in run.results:
        payload = step.payload if isinstance(step.payload, dict) else {}
        report_payloads[step.tool] = payload
        record_job_result(active_job, step, payload, jobs_root=jobs_root)
        step_statuses.append(
            step_completion_state(
                tool=str(getattr(step, "tool", "")),
                ok=bool(getattr(step, "ok", False)),
                payload=payload,
                outcome=str(getattr(step, "outcome", "")),
            )
        )
        total_elapsed_seconds += _step_elapsed_seconds(payload)
        if not first_error and getattr(step, "error", ""):
            first_error = str(getattr(step, "error", ""))

        if step.tool == "nmap":
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
        if not run.cancelled:
            evidence = build_evidence_graph(run.context.params.get("target", ""), report_payloads)
            report_payloads["correlation"] = evidence.to_dict()
            record_evidence_graph(active_job, evidence.to_dict(), jobs_root=jobs_root)
        render_recon_report(report_payloads, use_color=use_color)
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


def render_vector_round(investigation_round: object, *, use_color: bool | None = None) -> None:
    """Render a concise, explainable Vector decision without private traces."""
    decision = getattr(investigation_round, "decision", None)
    if decision is None:
        return
    number = int(getattr(investigation_round, "number", 0))
    discovered = len(getattr(getattr(decision, "delta", None), "services", ()))
    selected = tuple(getattr(decision, "selected", ()))
    write_segments(
        [("[vector]", "cyan"), (f" round {number} evaluated", "white")],
        use_color=use_color,
    )
    if discovered:
        write_line(f"         {discovered} services discovered", use_color=use_color)
    if not selected:
        write_line("         no high-value follow-ups remain", use_color=use_color)
        return
    write_line("         follow-up plan", use_color=use_color)
    for candidate in selected:
        label = _vector_candidate_label(candidate)
        target = str(getattr(candidate, "target", ""))
        dots = "." * max(3, 36 - len(label))
        write_segments(
            [("         ", "white"), (label, "white"), (f" {dots} {target}", "muted")],
            use_color=use_color,
        )


def _vector_candidate_label(candidate: object) -> str:
    intent = getattr(candidate, "intent", None)
    verb = str(getattr(intent, "verb", ""))
    subject = str(getattr(intent, "subject", ""))
    labels = {
        ("probe", "http"): "HTTP probe",
        ("probe", "https"): "HTTPS probe",
        ("fingerprint", "http"): "web fingerprint",
        ("fingerprint", "https"): "web fingerprint",
        ("inspect", "tls"): "TLS certificate inspection",
        ("collect", "network_intelligence_after_failure"): "network intelligence fallback",
        ("collect", "network_intelligence_after_empty_scan"): "network intelligence fallback",
    }
    return labels.get((verb, subject), f"{verb} {subject}".strip() or "follow-up")


class ReconProgressRenderer:
    """Render an in-place stateful preflight checklist in an interactive TTY."""

    def __init__(self, *, use_color: bool | None) -> None:
        self.enabled = use_color is not False and sys.stdout.isatty()
        self.total = 0
        self.steps: list[PlanStep] = []
        self.states: list[str] = []
        self.rendered = False
        self.rendered_lines = 0

    def show_plan(self, plan: ExecutionPlan) -> None:
        """Describe the planned checks before the first external tool runs."""
        if not self.enabled or not plan.steps:
            return
        self.total = len(plan.steps)
        self.steps = list(plan.steps)
        self.states = ["pending"] * self.total
        self._render(f"preparing {self.total} checks")

    def update(self, event: ExecutionProgress) -> None:
        """Refresh the in-place checklist after a step lifecycle event."""
        if not self.enabled:
            return
        self.total = event.total
        try:
            index = self.steps.index(event.step)
        except ValueError:
            return
        if event.state == "started":
            self.states[index] = "running"
        elif event.state == "completed":
            self.states[index] = _progress_state(event.result)
        self._render(f"preparing {self.total} checks")

    def finish(self, *, cancelled: bool = False) -> None:
        """Render the final checklist state before the report is printed."""
        if not self.enabled or not self.total:
            return
        if cancelled:
            self.states = ["skipped" if state == "pending" else state for state in self.states]
        completed = sum(state in {"done", "negative", "warning", "failed", "skipped"} for state in self.states)
        headline = "completed" if completed == self.total else "finished"
        self._render(f"{completed} checks {headline}")

    def _render(self, headline: str) -> None:
        if self.rendered:
            sys.stdout.write(f"\033[{self.rendered_lines}A\r")

        header = colorize("[plan]", "cyan", enabled=True) + colorize(f" {headline}", "white", enabled=True)
        sys.stdout.write(f"\033[2K{header}\n")
        for step, state in zip(self.steps, self.states):
            label = _progress_label(step)
            dots = "." * max(3, 32 - len(label))
            prefix = colorize(f"       {label} {dots} ", "muted", enabled=True)
            sys.stdout.write(f"\033[2K{prefix}{colorize(state, _progress_color(state), enabled=True)}\n")
        sys.stdout.flush()
        self.rendered = True
        self.rendered_lines = self.total + 1


def _progress_label(step: PlanStep) -> str:
    """Return the human-readable label used by the recon progress view."""
    labels = {
        "dns": "DNS lookup",
        "ipintel": "network intelligence",
        "http": "web probe",
        "httpx": "httpx service confirmation",
        "fingerprint": "web fingerprint",
        "whatweb": "WhatWeb fingerprint",
        "rpcinfo": "RPC program registry",
        "tls": "TLS certificate inspection",
        "rdap": "RDAP registration and ownership",
        "nmap": "service and system scan",
    }
    return labels.get(step.tool, step.action.replace("_", " "))


def _progress_state(result: object) -> str:
    """Return the user-facing completion state for one executed check."""
    if result is None:
        return "failed"
    payload = getattr(result, "payload", {})
    explicit = str(getattr(result, "outcome", "")).strip().lower()
    if explicit:
        return explicit
    return classify_result(
        tool=str(getattr(result, "tool", "")),
        ok=bool(getattr(result, "ok", False)),
        payload=payload if isinstance(payload, dict) else {},
        error=str(getattr(result, "error", "")),
    )


def _progress_color(state: str) -> str:
    """Return the deliberately restrained color for a checklist state."""
    return {
        "done": "green",
        "negative": "cyan",
        "running": "yellow",
        "warning": "yellow",
        "failed": "red",
        "skipped": "muted",
        "pending": "muted",
    }.get(state, "white")


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


def render_recon_context(params: dict[str, str], *, use_color: bool | None = None) -> None:
    """Render the concise context for one recon report."""
    target = params.get("target", "").strip()
    if target:
        write_segments([("[info]", "cyan"), (f" target {target}", "white")], use_color=use_color)

    details = []
    for key in ("strategy", "speed", "probe", "transport"):
        value = params.get(key, "").strip()
        if value:
            details.append(f"{key} {value}")
    if details:
        write_segments([("[info]", "cyan"), (f" {' · '.join(details)}", "white")], use_color=use_color)
    if target or details:
        write_line(use_color=use_color)


def render_recon_report(payloads: dict[str, dict], *, use_color: bool | None = None) -> None:
    """Render normalized findings while raw adapter output remains in the job."""
    ipintel = payloads.get("ipintel", {})
    dns = payloads.get("dns", {})
    http = payloads.get("http", {})
    httpx = payloads.get("httpx", {})
    fingerprint = payloads.get("fingerprint", {})
    whatweb = payloads.get("whatweb", {})
    rpcinfo = payloads.get("rpcinfo", {})
    tls = payloads.get("tls", {})
    rdap = payloads.get("rdap", {})
    correlation = payloads.get("correlation", {})
    nmap = payloads.get("nmap", {})

    if ipintel:
        _render_network_section(ipintel, use_color=use_color)
    if dns:
        _render_dns_report(dns, use_color=use_color)
    if http:
        _render_web_section(http, use_color=use_color)
    if httpx:
        _render_httpx_section(httpx, use_color=use_color)
    if fingerprint:
        _render_web_fingerprint_section(fingerprint, use_color=use_color)
    if whatweb:
        _render_whatweb_section(whatweb, use_color=use_color)
    if rpcinfo:
        _render_rpcinfo_section(rpcinfo, use_color=use_color)
    if tls:
        _render_tls_section(tls, use_color=use_color)
    if rdap:
        _render_rdap_sections(rdap, use_color=use_color)
    if correlation:
        _render_correlation_section(correlation, use_color=use_color)
    if nmap:
        _render_services_section(nmap, use_color=use_color)
        _render_system_section(nmap, use_color=use_color)
    if ipintel:
        _render_anonymity_section(ipintel, use_color=use_color)


def _render_network_section(payload: dict, *, use_color: bool | None = None) -> None:
    _render_section_header("network", _provider_names(payload), use_color=use_color)
    _render_field("address", str(payload.get("lookup_ip") or payload.get("target") or "unknown"), use_color=use_color)
    _render_field("scope", str(payload.get("location") or "unknown"), use_color=use_color)
    _render_field("asn", str(payload.get("asn") or "unknown"), use_color=use_color)
    latency = payload.get("latency")
    _render_field("latency", f"~{float(latency):.1f} ms" if isinstance(latency, (int, float)) else "unknown", use_color=use_color)
    if isinstance(payload.get("jitter"), (int, float)):
        _render_field("jitter", f"{float(payload['jitter']):.1f} ms", use_color=use_color)
    if isinstance(payload.get("bandwidth"), (int, float)):
        _render_field("bandwidth", f"~{float(payload['bandwidth']):.2f} Mbps", use_color=use_color)
    write_line(use_color=use_color)


def _render_dns_report(payload: dict, *, use_color: bool | None = None) -> None:
    _render_section_header("dns", _provider_names(payload), use_color=use_color)
    records = payload.get("records", {})
    if isinstance(records, dict):
        for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV"):
            values = records.get(record_type, [])
            if isinstance(values, list) and values:
                _render_field(record_type.lower(), ", ".join(str(value) for value in values), use_color=use_color)
    write_line(use_color=use_color)


def _render_web_section(payload: dict, *, use_color: bool | None = None) -> None:
    _render_section_header("web", _provider_names(payload), use_color=use_color)
    findings = payload.get("findings", [])
    rendered = False
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            scheme = urlsplit(str(finding.get("url", ""))).scheme or "http"
            status = finding.get("status_code")
            if isinstance(status, int):
                value = str(status)
                title = str(finding.get("title", "")).strip()
                redirect = str(finding.get("redirect_to", "")).strip()
                if title:
                    value = f"{value}  {title}"
                if redirect:
                    value = f"{value}  -> {redirect}"
            else:
                value = "closed"
            _render_field(scheme, value, use_color=use_color)
            rendered = True
    if not rendered:
        _render_field("status", "unavailable", use_color=use_color)
    write_line(use_color=use_color)


def _render_httpx_section(payload: dict, *, use_color: bool | None = None) -> None:
    """Render HTTP service confirmation from httpx without raw JSON noise."""
    _render_section_header("http services", _provider_names(payload, fallback="httpx"), use_color=use_color)
    if payload.get("skipped"):
        _render_field("status", "skipped (httpx unavailable; run install httpx)", use_color=use_color)
        write_line(use_color=use_color)
        return
    findings = payload.get("findings", [])
    if not isinstance(findings, list) or not findings:
        _render_field("status", "no HTTP service confirmed", use_color=use_color)
        write_line(use_color=use_color)
        return
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        endpoint = str(finding.get("url", "")).strip() or "unknown"
        status = str(finding.get("status_code") or "unknown")
        title = str(finding.get("title", "")).strip()
        value = status if not title else f"{status}  {title}"
        redirect = str(finding.get("redirect_to", "")).strip()
        if redirect:
            value = f"{value}  -> {redirect}"
        _render_field(endpoint, value, use_color=use_color)
        technologies = finding.get("technologies", [])
        if isinstance(technologies, list) and technologies:
            _render_field("technologies", ", ".join(str(item) for item in technologies), use_color=use_color)
        webserver = str(finding.get("webserver", "")).strip()
        if webserver:
            _render_field("server", webserver, use_color=use_color)
        tls = finding.get("tls", {})
        if isinstance(tls, dict):
            protocol = str(tls.get("protocol", tls.get("tls_version", ""))).strip()
            if protocol:
                _render_field("tls", protocol, use_color=use_color)
    write_line(use_color=use_color)


def _render_whatweb_section(payload: dict, *, use_color: bool | None = None) -> None:
    """Render WhatWeb technology evidence without exposing raw plugin JSON."""
    _render_section_header("whatweb", _provider_names(payload, fallback="whatweb"), use_color=use_color)
    if payload.get("skipped"):
        _render_field("status", "skipped (WhatWeb unavailable; run install whatweb)", use_color=use_color)
        write_line(use_color=use_color)
        return
    findings = payload.get("findings", [])
    if not isinstance(findings, list) or not findings:
        _render_field("status", "no web technologies identified", use_color=use_color)
        write_line(use_color=use_color)
        return
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        endpoint = str(finding.get("url", "")).strip() or "unknown"
        status = str(finding.get("status_code") or "unknown")
        title = str(finding.get("title", "")).strip()
        _render_field(endpoint, status if not title else f"{status}  {title}", use_color=use_color)
        technologies = finding.get("technologies", [])
        if isinstance(technologies, list) and technologies:
            _render_field("technologies", ", ".join(str(item) for item in technologies), use_color=use_color)
        server = str(finding.get("webserver", "")).strip()
        if server:
            _render_field("server", server, use_color=use_color)
    write_line(use_color=use_color)


def _render_rpcinfo_section(payload: dict, *, use_color: bool | None = None) -> None:
    """Render registered portmapper programs as concise structured evidence."""
    _render_section_header("rpc services", _provider_names(payload, fallback="rpcinfo"), use_color=use_color)
    if payload.get("skipped"):
        _render_field("status", "skipped (rpcinfo unavailable; run install rpcinfo)", use_color=use_color)
        write_line(use_color=use_color)
        return
    records = payload.get("registrations", [])
    if not isinstance(records, list) or not records:
        _render_field("status", "no RPC programs registered", use_color=use_color)
        write_line(use_color=use_color)
        return
    write_line("PROGRAM   VERS   PROTO   PORT    SERVICE", color="muted", use_color=use_color)
    for record in records:
        if not isinstance(record, dict):
            continue
        row = f"{str(record.get('program', '')).ljust(9)} {str(record.get('version', '')).ljust(6)} {str(record.get('protocol', '')).ljust(7)} {str(record.get('port', '')).ljust(7)} {record.get('service', '')}".rstrip()
        write_line(row, use_color=use_color)
    write_line(use_color=use_color)


def _render_tls_section(payload: dict, *, use_color: bool | None = None) -> None:
    """Render TLS facts without exposing the raw certificate parser output."""
    _render_section_header("tls", _tls_provider_names(payload), use_color=use_color)
    _render_field("endpoint", f"{payload.get('host') or payload.get('target') or 'unknown'}:{payload.get('port') or 443}", use_color=use_color)
    protocol = str(payload.get("protocol", "")).strip()
    cipher = str(payload.get("cipher", "")).strip()
    if protocol:
        _render_field("protocol", protocol, use_color=use_color)
    if cipher:
        _render_field("cipher", cipher, use_color=use_color)
    subject = str(payload.get("subject", "")).strip()
    issuer = str(payload.get("issuer", "")).strip()
    if subject:
        _render_field("subject", subject, use_color=use_color)
    if issuer:
        _render_field("issuer", issuer, use_color=use_color)
    sans = payload.get("sans", [])
    if isinstance(sans, list) and sans:
        _render_field("sans", ", ".join(str(value) for value in sans), use_color=use_color)
    not_after = str(payload.get("not_after", "")).strip()
    if not_after:
        expiry = not_after
        days = payload.get("days_until_expiry")
        if isinstance(days, int):
            expiry = f"{expiry} ({days} days)"
        _render_field("expiry", expiry, use_color=use_color)
    warnings = payload.get("warnings", [])
    if isinstance(warnings, list):
        for warning_text in warnings:
            _render_field("warning", str(warning_text), use_color=use_color)
    write_line(use_color=use_color)


def _render_web_fingerprint_section(payload: dict, *, use_color: bool | None = None) -> None:
    """Render technology claims alongside only their recorded confidence."""
    _render_section_header("web fingerprint", _provider_names(payload, fallback="urllib"), use_color=use_color)
    if payload.get("skipped"):
        _render_field("status", "skipped (no HTTP endpoint)", use_color=use_color)
        write_line(use_color=use_color)
        return
    for label, key in (("server", "server"), ("framework", "framework"), ("cms", "cms"), ("javascript", "javascript")):
        _render_field(label, str(payload.get(key) or "unknown"), use_color=use_color)
    security_headers = payload.get("security_headers", [])
    if isinstance(security_headers, list) and security_headers:
        _render_field("headers", ", ".join(str(value) for value in security_headers), use_color=use_color)
    cookies = payload.get("cookies", [])
    if isinstance(cookies, list) and cookies:
        _render_field("cookies", ", ".join(str(value) for value in cookies), use_color=use_color)
    _render_field("confidence", str(payload.get("confidence") or "low"), use_color=use_color)
    write_line(use_color=use_color)


def _render_rdap_sections(payload: dict, *, use_color: bool | None = None) -> None:
    """Render correlated domain registration and address ownership facts."""
    providers = _provider_names(payload, fallback="rdap.org")
    domain = str(payload.get("domain", "")).strip()
    if domain:
        _render_section_header("registration", providers, use_color=use_color)
        _render_field("domain", domain, use_color=use_color)
        _render_field("registrar", str(payload.get("registrar") or "unknown"), use_color=use_color)
        _render_field("created", str(payload.get("created") or "unknown"), use_color=use_color)
        _render_field("expires", str(payload.get("expires") or "unknown"), use_color=use_color)
        status = payload.get("status", [])
        _render_field("status", ", ".join(str(value) for value in status) if isinstance(status, list) and status else "unknown", use_color=use_color)
        write_line(use_color=use_color)
    address = str(payload.get("address", "")).strip()
    if address:
        _render_section_header("network ownership", providers, use_color=use_color)
        _render_field("address", address, use_color=use_color)
        _render_field("network", str(payload.get("network") or "unknown"), use_color=use_color)
        _render_field("organization", str(payload.get("organization") or "unknown"), use_color=use_color)
        _render_field("asn", str(payload.get("asn") or "unknown"), use_color=use_color)
        write_line(use_color=use_color)
    warnings = payload.get("warnings", [])
    if not domain and not address and isinstance(warnings, list) and warnings:
        _render_section_header("rdap", providers, use_color=use_color)
        _render_field("status", "unavailable", use_color=use_color)
        write_line(use_color=use_color)


def _render_correlation_section(payload: dict, *, use_color: bool | None = None) -> None:
    """Render the useful cross-tool joins, retaining individual claim provenance in storage."""
    claims = payload.get("claims", [])
    if not isinstance(claims, list):
        return
    normalized = [claim for claim in claims if isinstance(claim, dict)]
    if not normalized:
        return
    sources = tuple(dict.fromkeys(
        str(source)
        for claim in normalized
        for source in claim.get("sources", [])
        if str(source).strip()
    ))
    _render_section_header("correlation", sources, use_color=use_color)
    _render_field("target", str(payload.get("target") or "unknown"), use_color=use_color)
    _render_correlation_values("addresses", normalized, "resolves_to", use_color=use_color)
    _render_correlation_values("ownership", normalized, "owned_by", use_color=use_color)
    _render_correlation_values("asn", normalized, "announced_by", use_color=use_color)
    _render_correlation_values("web edge", normalized, "served_by", use_color=use_color)
    _render_correlation_values("framework", normalized, "uses_framework", use_color=use_color)
    _render_correlation_values("technology", normalized, "uses_technology", use_color=use_color)
    _render_correlation_values("rpc services", normalized, "exposes_rpc_service", use_color=use_color)
    _render_correlation_values("tls names", normalized, "presents_tls_name", use_color=use_color)
    write_line(use_color=use_color)


def _render_correlation_values(label: str, claims: list[dict], predicate: str, *, use_color: bool | None) -> None:
    values = tuple(dict.fromkeys(
        str(claim.get("value", "")).strip()
        for claim in claims
        if claim.get("predicate") == predicate and str(claim.get("value", "")).strip()
    ))
    if values:
        _render_field(label, ", ".join(values), use_color=use_color)


def _render_services_section(payload: dict, *, use_color: bool | None = None) -> None:
    _render_section_header("services", _provider_names(payload, fallback="nmap"), use_color=use_color)
    ports = payload.get("ports", [])
    interesting = [port for port in ports if isinstance(port, dict) and str(port.get("state", "")).lower() in {"open", "filtered"}] if isinstance(ports, list) else []
    if not interesting:
        write_line("no open services found", color="muted", use_color=use_color)
        write_line(use_color=use_color)
        return
    write_line("PORT     STATE    SERVICE    VERSION", color="muted", use_color=use_color)
    for port in interesting:
        label = f"{port.get('port', '')}/{port.get('protocol', '')}"
        state = str(port.get("state", ""))
        service = str(port.get("service", ""))
        version = str(port.get("version", ""))
        write_line(f"{label.ljust(8)} {state.ljust(8)} {service.ljust(10)} {version}".rstrip(), use_color=use_color)
    write_line(use_color=use_color)


def _render_system_section(payload: dict, *, use_color: bool | None = None) -> None:
    system = payload.get("system", {})
    if not isinstance(system, dict):
        return
    rows = [(label, str(system.get(key, "")).strip()) for label, key in (("device", "device"), ("os", "os"), ("kernel", "kernel"), ("cpe", "cpe"), ("distance", "distance"))]
    rows = [(label, value) for label, value in rows if value]
    if not rows:
        return
    _render_section_header("system", _provider_names(payload, fallback="nmap"), use_color=use_color)
    for label, value in rows:
        _render_field(label, value, use_color=use_color)
    write_line(use_color=use_color)


def _render_anonymity_section(payload: dict, *, use_color: bool | None = None) -> None:
    _render_section_header("anonymity", _provider_names(payload), use_color=use_color)
    vpn = payload.get("vpn_likely")
    vpn_text = "likely" if vpn is True else "unlikely" if vpn is False else "unknown"
    _render_field("vpn", vpn_text, use_color=use_color)
    _render_field("confidence", str(payload.get("confidence") or "unknown"), use_color=use_color)
    write_line(use_color=use_color)


def _render_section_header(title: str, providers: tuple[str, ...], *, use_color: bool | None = None) -> None:
    source_label = "source" if len(providers) == 1 else "sources"
    annotation = f"  ({source_label}: {', '.join(providers)})" if providers else ""
    write_segments([(title, "cyan"), (annotation, "muted")], use_color=use_color)
    write_line("─" * len(title), color="muted", use_color=use_color)


def _render_field(label: str, value: str, *, use_color: bool | None = None) -> None:
    write_segments([(f"{label.ljust(11)}", "muted"), (": ", "muted"), (value, "white")], use_color=use_color)


def _provider_names(payload: dict, *, fallback: str = "") -> tuple[str, ...]:
    provider = str(payload.get("provider", "")).strip()
    if not provider:
        provider = fallback
    return (provider,) if provider else ()


def _tls_provider_names(payload: dict) -> tuple[str, ...]:
    """Report precisely which TLS components produced the displayed facts."""
    providers = list(_provider_names(payload, fallback="python ssl"))
    parser = str(payload.get("certificate_parser", "")).strip()
    if parser and parser not in providers:
        providers.append(parser)
    return tuple(providers)


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
    summary = "recon complete"
    if completion_state == "completed_with_warnings":
        summary = "recon complete with warnings"
    elif completion_state == "partial":
        summary = "recon partial"
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
                "outcome": payload.get("outcome", ""),
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

    if getattr(step, "tool", "") == "tls":
        entry = {
            "recorded_at": datetime.now().isoformat(timespec="seconds"),
            "module": "recon",
            "tool": getattr(step, "tool", ""),
            "action": getattr(step, "action", ""),
            "ok": bool(getattr(step, "ok", False)),
            "error": str(getattr(step, "error", "")),
            "summary": {
                "target": payload.get("target", ""),
                "endpoint": f"{payload.get('host', '')}:{payload.get('port', '')}",
                "protocol": payload.get("protocol", ""),
                "cipher": payload.get("cipher", ""),
                "not_after": payload.get("not_after", ""),
                "elapsed_seconds": payload.get("elapsed_seconds"),
            },
            "payload": payload,
        }
        append_job_result(active_job, entry, jobs_root=jobs_root)
        return

    if getattr(step, "tool", "") == "fingerprint":
        entry = {
            "recorded_at": datetime.now().isoformat(timespec="seconds"),
            "module": "recon",
            "tool": getattr(step, "tool", ""),
            "action": getattr(step, "action", ""),
            "ok": bool(getattr(step, "ok", False)),
            "error": str(getattr(step, "error", "")),
            "summary": {
                "target": payload.get("target", ""),
                "server": payload.get("server", ""),
                "framework": payload.get("framework", ""),
                "cms": payload.get("cms", ""),
                "javascript": payload.get("javascript", ""),
                "confidence": payload.get("confidence", ""),
                "elapsed_seconds": payload.get("elapsed_seconds"),
            },
            "payload": payload,
        }
        append_job_result(active_job, entry, jobs_root=jobs_root)
        return

    if getattr(step, "tool", "") == "rdap":
        entry = {
            "recorded_at": datetime.now().isoformat(timespec="seconds"),
            "module": "recon",
            "tool": getattr(step, "tool", ""),
            "action": getattr(step, "action", ""),
            "ok": bool(getattr(step, "ok", False)),
            "error": str(getattr(step, "error", "")),
            "summary": {
                "target": payload.get("target", ""),
                "domain": payload.get("domain", ""),
                "address": payload.get("address", ""),
                "registrar": payload.get("registrar", ""),
                "organization": payload.get("organization", ""),
                "asn": payload.get("asn", ""),
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


def record_evidence_graph(active_job: str, payload: dict[str, object], *, jobs_root: Path | None = None) -> None:
    """Persist the derived graph as a first-class job result, without re-running a tool."""
    if not active_job:
        return
    claims = payload.get("claims", [])
    claim_count = len(claims) if isinstance(claims, list) else 0
    append_job_result(
        active_job,
        {
            "recorded_at": datetime.now().isoformat(timespec="seconds"),
            "module": "recon",
            "tool": "evidence",
            "action": "correlation",
            "ok": True,
            "error": "",
            "summary": {"target": payload.get("target", ""), "claim_count": claim_count},
            "payload": {**payload, "warnings": [], "elapsed_seconds": 0.0},
        },
        jobs_root=jobs_root,
    )


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
