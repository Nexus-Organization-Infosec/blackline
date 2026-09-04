"""Job context commands."""

from __future__ import annotations

import json
import random
import string
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from blackline.cli.commands.system.help_cmd import load_help_groups
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.cli.ui.display import error, info, result, write_line, write_segments
from blackline.config.tool_loader import load_tools_config
from blackline.core.recon import InvalidReconTargetError, build_recon_pipeline
from blackline.core.recon.outcomes import classify_result, completion_state_for

ID_ALPHABET = string.ascii_uppercase + string.digits
MANUAL_MODULE = "manual"
COMPLETION_STATES = {"initialized", "completed", "completed_with_warnings", "partial", "failed"}


@dataclass(frozen=True, slots=True)
class Job:
    """Structured record of execution context and results."""

    id: str
    module: str
    params: dict[str, str]
    created: str
    status: str = "initialized"
    target: str = ""
    target_type: str = ""
    steps: list[dict[str, object]] = field(default_factory=list)
    summary: dict[str, object] = field(default_factory=dict)
    ipintel: dict[str, object] = field(default_factory=dict)
    results: list[dict[str, object]] = field(default_factory=list)


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
        summary=_build_job_summary(target=target, target_type=target_type, steps=(), legacy_results=()),
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
    for identifier in identifiers:
        path = jobs_root / f"{identifier}.json"
        if not path.exists():
            missing.append(identifier)
            continue

        path.unlink()
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
    summary = _job_summary(job)
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


def save_job(job: Job, jobs_root: Path) -> Path:
    """Persist a job as JSON."""
    path = jobs_root / f"{job.id}.json"
    path.write_text(json.dumps(asdict(job), indent=2) + "\n", encoding="utf-8")
    return path


def append_job_result(identifier: str, entry: dict[str, object], jobs_root: Path | None = None) -> bool:
    """Append one structured result entry to a persisted job."""
    jobs_root = jobs_root or default_jobs_root()
    job = load_job(identifier, jobs_root)
    if job is None:
        return False

    entry = dict(entry)
    entry.setdefault("outcome", _step_outcome_from_entry(entry))
    step = _normalize_step_entry(entry)
    steps = [*job.steps, step]
    summary = _build_job_summary(
        target=job.target,
        target_type=job.target_type,
        steps=steps,
        legacy_results=[*job.results, entry],
    )
    updated = Job(
        id=job.id,
        module=job.module,
        params=job.params,
        created=job.created,
        status=_derive_job_status(steps),
        target=job.target,
        target_type=job.target_type,
        steps=steps,
        summary=summary,
        ipintel=_updated_ipintel(job.ipintel, entry),
        results=[*job.results, entry],
    )
    save_job(updated, jobs_root)
    return True


def step_completion_state(*, tool: str, ok: bool, payload: dict[str, object], outcome: str = "") -> str:
    """Return the normalized completion state for one executed recon step."""
    result_outcome = outcome or classify_result(tool=tool, ok=ok, payload=payload)
    return completion_state_for(result_outcome)


def derive_completion_state(statuses: list[str]) -> str:
    """Return the aggregate completion state for a sequence of step states."""
    if not statuses:
        return "initialized"

    if all(status == "completed" for status in statuses):
        return "completed"
    if any(status == "failed" for status in statuses):
        if any(status in {"completed", "completed_with_warnings", "partial"} for status in statuses):
            return "partial"
        return "failed"
    if any(status == "partial" for status in statuses):
        return "partial"
    if any(status == "completed_with_warnings" for status in statuses):
        return "completed_with_warnings"
    return "initialized"


def load_job(identifier: str, jobs_root: Path) -> Job | None:
    """Load one persisted job."""
    path = jobs_root / f"{normalize_job_id(identifier)}.json"
    if not path.exists():
        return None

    data = json.loads(path.read_text(encoding="utf-8"))
    params = {str(key): str(value) for key, value in _mapping(data.get("params")).items()}
    target = str(data.get("target", "")) or params.get("target", "")
    target_type = str(data.get("target_type", "")) or _infer_target_type(target)
    legacy_results = _list_of_dicts(data.get("results"))
    steps = _list_of_dicts(data.get("steps")) or _legacy_steps_from_results(legacy_results)
    summary = _mapping(data.get("summary")) or _build_job_summary(
        target=target,
        target_type=target_type,
        steps=steps,
        legacy_results=legacy_results,
    )
    status = str(data.get("status", "initialized"))
    if status not in COMPLETION_STATES:
        status = "initialized"
    if status == "initialized" and steps:
        status = _derive_job_status(steps)

    return Job(
        id=str(data.get("id", "")),
        module=str(data.get("module", "")),
        params=params,
        created=str(data.get("created", "")),
        status=status,
        target=target,
        target_type=target_type,
        steps=steps,
        summary=summary,
        ipintel=_mapping(data.get("ipintel")),
        results=legacy_results,
    )


def list_jobs(jobs_root: Path | None = None) -> list[Job]:
    """Return persisted jobs sorted by id."""
    jobs_root = jobs_root or default_jobs_root()
    if not jobs_root.exists():
        return []
    return [job for path in sorted(jobs_root.glob("*.json")) if (job := load_job(path.stem, jobs_root))]


def list_job_ids(jobs_root: Path | None = None) -> list[str]:
    """Return persisted job ids."""
    return [job.id for job in list_jobs(jobs_root)]


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


def generate_job_id(jobs_root: Path) -> str:
    """Generate a short human-readable job id."""
    while True:
        identifier = "".join(random.choice(ID_ALPHABET) for _ in range(4))
        if not (jobs_root / f"{identifier}.json").exists():
            return identifier


def available_modules() -> set[str]:
    """Return modules that can be used to create jobs."""
    modules: set[str] = set()
    for group in load_help_groups():
        if group.id == "tools":
            modules.update(item.name for item in group.items)
    modules.update(_configured_tool_modules())
    return modules


def normalize_job_id(identifier: str) -> str:
    """Normalize user-entered job identifiers."""
    return identifier.strip().upper().removeprefix("#")


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


def default_jobs_root() -> Path:
    """Return the default job storage path."""
    return Path(__file__).resolve().parents[3] / "storage" / "jobs"


def _normalize_step_entry(entry: dict[str, object]) -> dict[str, object]:
    if "name" in entry and "status" in entry and "provenance" in entry:
        return dict(entry)

    payload = _mapping(entry.get("payload"))
    results = payload.get("ports")
    if not isinstance(results, list):
        results = []
    summary = _mapping(entry.get("summary"))
    recorded_at = str(entry.get("recorded_at", datetime.now().isoformat(timespec="seconds")))
    tool = str(entry.get("tool", ""))
    status = _step_status_from_entry(entry)
    outcome = _step_outcome_from_entry(entry)
    command = payload.get("command", [])
    command_text = " ".join(str(item) for item in command) if isinstance(command, list) else str(command)

    return {
        "name": _step_name(tool, str(entry.get("action", ""))),
        "status": status,
        "outcome": outcome,
        "error": str(entry.get("error", "")),
        "command": command_text,
        "summary": summary,
        "results": [item for item in results if isinstance(item, dict)],
        "raw_output": str(payload.get("raw_output", "")),
        "provenance": {
            "tool": tool,
            "timestamp": recorded_at,
            "confidence": str(entry.get("confidence", "")),
        },
    }


def _legacy_steps_from_results(results: list[dict[str, object]]) -> list[dict[str, object]]:
    return [_normalize_step_entry(entry) for entry in results]


def _derive_job_status(steps: list[dict[str, object]]) -> str:
    return derive_completion_state([str(step.get("status", "initialized")) for step in steps])


def _step_status_from_entry(entry: dict[str, object]) -> str:
    payload = _mapping(entry.get("payload"))
    return step_completion_state(
        tool=str(entry.get("tool", "")),
        ok=bool(entry.get("ok", False)),
        payload=payload,
        outcome=str(entry.get("outcome", "")),
    )


def _step_outcome_from_entry(entry: dict[str, object]) -> str:
    payload = _mapping(entry.get("payload"))
    return str(entry.get("outcome", "")).strip() or classify_result(
        tool=str(entry.get("tool", "")),
        ok=bool(entry.get("ok", False)),
        payload=payload,
        error=str(entry.get("error", "")),
    )


def _step_name(tool: str, action: str) -> str:
    if tool == "nmap":
        return "port_scan"
    if action:
        return action
    if tool:
        return tool
    return "step"


def _build_job_summary(
    *,
    target: str,
    target_type: str,
    steps: tuple[dict[str, object], ...] | list[dict[str, object]],
    legacy_results: tuple[dict[str, object], ...] | list[dict[str, object]],
) -> dict[str, object]:
    step_list = list(steps)
    summary: dict[str, object] = {
        "step_count": len(step_list),
        "result_count": _count_job_results(step_list, list(legacy_results)),
    }
    if target:
        summary["target"] = target
    if target_type:
        summary["target_type"] = target_type

    open_ports = 0
    filtered_ports = 0
    elapsed_seconds = 0.0
    host_status = ""
    completed_steps = 0
    negative_steps = 0
    skipped_steps = 0
    warning_steps = 0
    failed_steps = 0
    for step in step_list:
        step_status = str(step.get("status", "initialized"))
        outcome = str(step.get("outcome", "done"))
        if step_status == "completed":
            if outcome == "negative":
                negative_steps += 1
            elif outcome == "skipped":
                skipped_steps += 1
            else:
                completed_steps += 1
        elif step_status == "completed_with_warnings":
            warning_steps += 1
        elif step_status == "failed":
            failed_steps += 1

        for result_item in step.get("results", []):
            if not isinstance(result_item, dict):
                continue
            state = str(result_item.get("state", "")).lower()
            if state == "open":
                open_ports += 1
            elif state == "filtered":
                filtered_ports += 1

        step_summary = _mapping(step.get("summary"))
        if step_summary.get("host_status"):
            host_status = str(step_summary.get("host_status", ""))
        if isinstance(step_summary.get("elapsed_seconds"), (int, float)):
            elapsed_seconds += float(step_summary.get("elapsed_seconds", 0.0))

    if open_ports:
        summary["open_ports"] = open_ports
    if filtered_ports:
        summary["filtered_ports"] = filtered_ports
    if host_status:
        summary["host_status"] = host_status
    if elapsed_seconds > 0:
        summary["elapsed_seconds"] = elapsed_seconds
    if completed_steps:
        summary["completed_steps"] = completed_steps
    if negative_steps:
        summary["negative_steps"] = negative_steps
    if skipped_steps:
        summary["skipped_steps"] = skipped_steps
    if warning_steps:
        summary["warning_steps"] = warning_steps
    if failed_steps:
        summary["failed_steps"] = failed_steps
    return summary


def _job_summary(job: Job) -> dict[str, object]:
    return job.summary or _build_job_summary(
        target=job.target,
        target_type=job.target_type,
        steps=job.steps,
        legacy_results=job.results,
    )


def _count_job_results(steps: list[dict[str, object]], legacy_results: list[dict[str, object]]) -> int:
    count = sum(1 for step in steps if step.get("results") or step.get("summary") or step.get("error"))
    if count:
        return count
    return len(legacy_results)


def _updated_ipintel(current: dict[str, object], entry: dict[str, object]) -> dict[str, object]:
    if str(entry.get("tool", "")) != "ipintel":
        return current
    payload = _mapping(entry.get("payload"))
    return {
        "lookup_ip": payload.get("lookup_ip", ""),
        "asn": payload.get("asn", ""),
        "org": payload.get("org", ""),
        "domain": payload.get("domain", ""),
        "location": payload.get("location", ""),
        "latency": payload.get("latency"),
        "vpn_likely": payload.get("vpn_likely"),
        "confidence": payload.get("confidence", ""),
        "jitter": payload.get("jitter"),
        "bandwidth": payload.get("bandwidth"),
        "mss": payload.get("mss"),
        "trace": payload.get("trace", []),
        "provider": payload.get("provider", ""),
        "raw": payload.get("raw", {}),
    }


def _infer_target_type(target: str) -> str:
    if not target:
        return ""
    try:
        return build_recon_pipeline(target).target.target_type
    except InvalidReconTargetError:
        return ""


def _mapping(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


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
