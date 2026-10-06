"""Job context commands."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from blackline.cli.commands.system.help_cmd import load_help_groups
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.cli.ui.display import error, info, result, write_line, write_segments
from blackline.config.tool_loader import load_tools_config
from blackline.core.recon import InvalidReconTargetError, build_recon_pipeline
from blackline.core.jobs import (
    Job,
    build_job_summary,
    derive_completion_state,
    job_summary,
    normalize_job_id,
    step_completion_state,
)
from blackline.storage.job_store import (
    append_job_result,
    default_jobs_root,
    generate_job_id,
    list_job_ids,
    list_jobs,
    load_job,
    repository,
    save_job,
)

MANUAL_MODULE = "manual"


def handle_new(
    expression: str,
    state: ShellState,
    *,
    jobs_root: Path | None = None,
    created_at: datetime | None = None,
    job_id: str | None = None,
    render_summary: bool = True,
    announce_entry: bool = True,
    use_color: bool | None = None,
) -> bool:
    """Create a job and enter it as the active shell context."""
    parsed = parse_job_expression(expression)
    if not parsed:
        module, params = MANUAL_MODULE, {}
    else:
        module, params = parsed

    if module != MANUAL_MODULE and module not in available_modules():
        error(f"module not found: {module}", use_color=use_color)
        return False

    if module == "recon" and not params.get("target"):
        info("missing required fields → entering interactive mode", use_color=use_color)
        return False

    normalized_target = None
    if module == "recon" and params.get("target"):
        try:
            normalized_target = build_recon_pipeline(params["target"]).target
        except InvalidReconTargetError as exc:
            error(str(exc), use_color=use_color)
            return False

    jobs_root = jobs_root or default_jobs_root()
    jobs_root.mkdir(parents=True, exist_ok=True)
    identifier = job_id or generate_job_id(jobs_root)
    created = (created_at or datetime.now()).strftime("%Y-%m-%d %H:%M")
    target = params.get("target", "")
    target_type = normalized_target.target_type if normalized_target else ""
    job = Job(
        id=identifier,
        module=module,
        params=params,
        created=created,
        target=target,
        target_type=target_type,
        summary=build_job_summary(target=target, target_type=target_type, steps=(), legacy_results=()),
    )
    save_job(job, jobs_root)
    state.active_job = identifier
    if render_summary:
        render_job(job, use_color=use_color)
    if announce_entry:
        info(f"entered job #{identifier}", use_color=use_color)
    return True


def handle_show(
    state: ShellState,
    selector: str = "",
    *,
    jobs_root: Path | None = None,
    use_color: bool | None = None,
) -> None:
    """Show a job summary, one report section, raw evidence, or source provenance."""
    target_id, view = _parse_show_selector(selector, active_job=state.active_job)
    if not target_id:
        info("no active job", use_color=use_color)
        return

    job = load_job(target_id, jobs_root or default_jobs_root())
    if not job:
        error(f"job not found: #{target_id}", use_color=use_color)
        return
    if not view:
        render_job(job, use_color=use_color)
    elif view == "sources":
        render_job_sources(job, use_color=use_color)
    elif view == "raw":
        render_job_raw(job, use_color=use_color)
    elif view == "formatted":
        render_job_formatted(job, use_color=use_color)
    else:
        render_job_section(job, view, use_color=use_color)


def _parse_show_selector(selector: str, *, active_job: str) -> tuple[str, str]:
    """Parse ``show [#ID] [view]`` without treating a view as a job identifier."""
    tokens = selector.strip().split(maxsplit=1)
    if tokens and tokens[0].startswith("#"):
        return normalize_job_id(tokens[0]) or active_job, tokens[1].strip().lower() if len(tokens) > 1 else ""
    return active_job, selector.strip().lower()


def render_job_sources(job: Job, *, use_color: bool | None = None) -> None:
    """Render each persisted result section with its exact provider(s)."""
    write_line("sources", color="cyan", use_color=use_color)
    write_line("───────", color="muted", use_color=use_color)
    rendered = False
    for entry in job.results:
        if not isinstance(entry, dict):
            continue
        tool = str(entry.get("tool", "")).strip()
        payload = _mapping(entry.get("payload"))
        providers = _entry_sources(payload)
        if tool and providers:
            write_line(f"{tool.ljust(13)}: {', '.join(providers)}", use_color=use_color)
            rendered = True
    if not rendered:
        write_line("no source data recorded", color="muted", use_color=use_color)
    write_line(use_color=use_color)


def render_job_raw(job: Job, *, use_color: bool | None = None) -> None:
    """Render stored raw artifacts only when the operator explicitly asks for them."""
    rendered = False
    for entry in job.results:
        if not isinstance(entry, dict):
            continue
        tool = str(entry.get("tool", "")).strip() or "unknown"
        payload = _mapping(entry.get("payload"))
        artifacts: list[tuple[str, object]] = []
        raw_output = payload.get("raw_output")
        if isinstance(raw_output, str) and raw_output.strip():
            artifacts.append(("raw_output", raw_output.strip()))
        raw = payload.get("raw")
        if isinstance(raw, dict) and raw:
            artifacts.append(("raw", raw))
        if not artifacts:
            continue
        rendered = True
        write_line(f"raw {tool}", color="cyan", use_color=use_color)
        write_line("─" * (4 + len(tool)), color="muted", use_color=use_color)
        for label, artifact in artifacts:
            if label == "raw":
                write_line(json.dumps(artifact, indent=2, sort_keys=True), use_color=use_color)
            else:
                write_line(str(artifact), use_color=use_color)
        write_line(use_color=use_color)
    if not rendered:
        info("no raw artifacts recorded", use_color=use_color)


def render_job_formatted(job: Job, *, use_color: bool | None = None) -> None:
    """Replay the saved final recon presentation without raw or live-progress output."""
    if job.module != "recon":
        info(f"no formatted recon output recorded for #{job.id}", use_color=use_color)
        return
    payloads: dict[str, dict] = {}
    last_nmap_payload: dict[str, object] = {}
    for entry in job.results:
        if not isinstance(entry, dict):
            continue
        tool = str(entry.get("tool", "")).strip()
        payload = _mapping(entry.get("payload"))
        if not tool or not payload:
            continue
        payloads["correlation" if tool == "evidence" else tool] = payload
        if tool == "nmap" and bool(entry.get("ok", False)):
            last_nmap_payload = payload
    if not payloads:
        info(f"no formatted recon output recorded for #{job.id}", use_color=use_color)
        return

    # Import lazily: recon imports this module to persist its results.
    from blackline.cli.commands.recon import recon_cmd

    recon_cmd.render_recon_context(job.params, use_color=use_color)
    recon_cmd.render_recon_report(payloads, use_color=use_color)
    recon_cmd.render_recon_summary(
        job.status,
        nmap_payload=last_nmap_payload,
        active_job=job.id,
        use_color=use_color,
    )


def render_job_section(job: Job, view: str, *, use_color: bool | None = None) -> None:
    """Render one persisted recon section using the same curated report renderer."""
    tool = _SHOW_SECTION_TO_TOOL.get(view)
    if tool is None:
        error("unknown show view: " + view + " (use formatted, sources, raw, or a report section)", use_color=use_color)
        return
    entry = next((entry for entry in reversed(job.results) if isinstance(entry, dict) and entry.get("tool") == tool), None)
    if entry is None:
        info(f"no {view} data recorded for #{job.id}", use_color=use_color)
        return
    payload = _mapping(entry.get("payload"))
    # Import lazily: recon itself imports the jobs module for persistence.
    from blackline.cli.commands.recon import recon_cmd

    exact_renderers = {
        "network": recon_cmd._render_network_section,
        "web": recon_cmd._render_web_section,
        "fingerprint": recon_cmd._render_web_fingerprint_section,
        "tls": recon_cmd._render_tls_section,
        "services": recon_cmd._render_services_section,
        "system": recon_cmd._render_system_section,
    }
    renderer = exact_renderers.get(view)
    if renderer is not None:
        renderer(payload, use_color=use_color)
        return
    report_key = "correlation" if tool == "evidence" else tool
    recon_cmd.render_recon_report({report_key: payload}, use_color=use_color)


def _entry_sources(payload: dict[str, object]) -> tuple[str, ...]:
    sources: list[str] = []
    provider = str(payload.get("provider", "")).strip()
    parser = str(payload.get("certificate_parser", "")).strip()
    if provider:
        sources.append(provider)
    if parser:
        sources.append(parser)
    claims = payload.get("claims", [])
    if isinstance(claims, list):
        for claim in claims:
            if isinstance(claim, dict):
                claim_sources = claim.get("sources", [])
                if isinstance(claim_sources, list):
                    sources.extend(str(source).strip() for source in claim_sources if str(source).strip())
    return tuple(dict.fromkeys(sources))


_SHOW_SECTION_TO_TOOL = {
    "formatted": "formatted",
    "dns": "dns",
    "network": "ipintel",
    "ipintel": "ipintel",
    "web": "http",
    "http": "http",
    "fingerprint": "fingerprint",
    "web fingerprint": "fingerprint",
    "tls": "tls",
    "registration": "rdap",
    "ownership": "rdap",
    "rdap": "rdap",
    "services": "nmap",
    "system": "nmap",
    "correlation": "evidence",
}


def handle_jobs(*, jobs_root: Path | None = None, use_color: bool | None = None) -> None:
    """List stored jobs."""
    jobs_root = jobs_root or default_jobs_root()
    jobs = list_jobs(jobs_root)
    if not jobs:
        info("no jobs yet", use_color=use_color)
        return

    width = max(len(job.id) for job in jobs)
    for job in jobs:
        write_segments(
            [
                (f"#{job.id}".ljust(width + 1), "cyan"),
                ("  ", "muted"),
                (job.module.ljust(8), "white"),
                ("  ", "muted"),
                (job.status, "muted"),
            ],
            use_color=use_color,
        )


def handle_enter(
    identifier: str,
    state: ShellState,
    *,
    jobs_root: Path | None = None,
    use_color: bool | None = None,
) -> bool:
    """Enter an existing job context."""
    clean_id = normalize_job_id(identifier)
    if not clean_id:
        error("usage: enter #ID", use_color=use_color)
        return False

    if not load_job(clean_id, jobs_root or default_jobs_root()):
        error(f"job not found: #{clean_id}", use_color=use_color)
        return False

    state.active_job = clean_id
    info(f"entered job #{clean_id}", use_color=use_color)
    return True


def handle_delete_job(
    expression: str,
    state: ShellState,
    *,
    jobs_root: Path | None = None,
    use_color: bool | None = None,
) -> bool:
    """Delete one or more persisted jobs."""
    jobs_root = jobs_root or default_jobs_root()
    identifiers = parse_delete_targets(expression, jobs_root)
    if not identifiers:
        error("usage: delete #ID[, #ID] or delete *", use_color=use_color)
        return False

    deleted: list[str] = []
    missing: list[str] = []
    job_repository = repository(jobs_root)
    for identifier in identifiers:
        if not job_repository.delete(identifier):
            missing.append(identifier)
            continue
        deleted.append(identifier)

    if state.active_job in deleted:
        identifier = state.active_job
        state.active_job = ""
        info(f"left job #{identifier}", use_color=use_color)

    for identifier in deleted:
        result(f"job deleted: #{identifier}", use_color=use_color)

    for identifier in missing:
        error(f"job not found: #{identifier}", use_color=use_color)

    return bool(deleted) and not missing


def handle_leave_job(state: ShellState, *, use_color: bool | None = None) -> bool:
    """Leave the active job context when one is active."""
    if not state.active_job:
        return False
    identifier = state.active_job
    state.active_job = ""
    info(f"left job #{identifier}", use_color=use_color)
    return True


def parse_job_expression(expression: str) -> tuple[str, dict[str, str]] | None:
    """Parse module[key=value] expressions."""
    expression = expression.strip()
    if not expression:
        return None

    if "[" not in expression:
        return expression, {}

    if not expression.endswith("]"):
        return None

    module, raw_params = expression.split("[", 1)
    module = module.strip()
    raw_params = raw_params[:-1].strip()
    if not module:
        return None

    params: dict[str, str] = {}
    if raw_params:
        for pair in raw_params.split(","):
            if "=" not in pair:
                return None
            key, value = pair.split("=", 1)
            params[key.strip()] = value.strip()
    return module, params


def render_job(job: Job, *, use_color: bool | None = None) -> None:
    """Render a compact job summary."""
    summary = job_summary(job)
    write_line("[job]", use_color=use_color)
    write_line(use_color=use_color)
    _job_row("id", f"#{job.id}", value_color="cyan", use_color=use_color)
    _job_row("module", job.module, use_color=use_color)
    if job.target:
        _job_row("target", job.target, use_color=use_color)
    if job.target_type:
        _job_row("type", job.target_type, use_color=use_color)
    for key, value in job.params.items():
        if key == "target":
            continue
        _job_row(key, value, use_color=use_color)
    _job_row("created", job.created, use_color=use_color)
    write_line(use_color=use_color)
    _job_row("status", job.status, use_color=use_color)
    _job_row("steps", str(summary.get("step_count", 0)), use_color=use_color)
    _job_row("results", str(summary.get("result_count", 0)), use_color=use_color)
    if "open_ports" in summary:
        _job_row("open", str(summary.get("open_ports", 0)), use_color=use_color)
    if "filtered_ports" in summary:
        _job_row("filtered", str(summary.get("filtered_ports", 0)), use_color=use_color)
    if "elapsed_seconds" in summary:
        _job_row("elapsed", _format_elapsed(float(summary.get("elapsed_seconds", 0.0))), use_color=use_color)
    if job.ipintel:
        asn = " ".join(part for part in (str(job.ipintel.get("asn", "")).strip(), str(job.ipintel.get("org", "")).strip()) if part)
        if asn:
            _job_row("asn", asn, use_color=use_color)
        location = str(job.ipintel.get("location", "")).strip()
        if location:
            _job_row("location", location, use_color=use_color)
        lookup_ip = str(job.ipintel.get("lookup_ip", "")).strip()
        if lookup_ip:
            _job_row("lookup_ip", lookup_ip, use_color=use_color)
    write_line(use_color=use_color)


def parse_delete_targets(expression: str, jobs_root: Path | None = None) -> list[str]:
    """Parse delete targets from comma-separated ids or '*'."""
    expression = expression.strip()
    if not expression:
        return []
    if expression == "*":
        return list_job_ids(jobs_root)

    targets: list[str] = []
    for raw in expression.split(","):
        identifier = normalize_job_id(raw)
        if identifier:
            targets.append(identifier)
    return targets


def available_modules() -> set[str]:
    """Return modules that can be used to create jobs."""
    modules: set[str] = set()
    for group in load_help_groups():
        if group.id == "tools":
            modules.update(item.name for item in group.items)
    modules.update(_configured_tool_modules())
    return modules


def _configured_tool_modules() -> set[str]:
    """Return user-facing modules discovered from tool configuration."""
    raw_tools = load_tools_config().get("tools", {})
    if not isinstance(raw_tools, dict):
        return set()

    modules: set[str] = set()
    for name, config in raw_tools.items():
        if not isinstance(config, dict):
            continue
        if isinstance(config.get("arguments"), dict) or isinstance(config.get("engine"), dict):
            modules.add(str(name))
    return modules


def _mapping(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _format_elapsed(seconds: float) -> str:
    if seconds >= 60:
        minutes = int(seconds // 60)
        remainder = seconds - (minutes * 60)
        return f"{minutes}m {remainder:.1f}s"
    return f"{seconds:.1f}s"


def _job_row(label: str, value: str, *, value_color: str = "white", use_color: bool | None = None) -> None:
    write_segments(
        [
            (label.ljust(8), "muted"),
            (" : ", "muted"),
            (value, value_color),
        ],
        use_color=use_color,
    )
