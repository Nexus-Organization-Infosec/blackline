"""Stable job records and result-aggregation rules."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime

from blackline.core.recon import InvalidReconTargetError, build_recon_pipeline
from blackline.core.recon.outcomes import classify_result, completion_state_for

COMPLETION_STATES = frozenset({"initialized", "completed", "completed_with_warnings", "partial", "failed"})


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
    schema_version: int = 1

    def to_dict(self) -> dict[str, object]:
        """Return the versioned JSON-compatible representation."""
        return {
            "id": self.id,
            "module": self.module,
            "params": dict(self.params),
            "created": self.created,
            "status": self.status,
            "target": self.target,
            "target_type": self.target_type,
            "steps": list(self.steps),
            "summary": dict(self.summary),
            "ipintel": dict(self.ipintel),
            "results": list(self.results),
            "schema_version": self.schema_version,
        }


def job_from_dict(data: dict[str, object]) -> Job:
    """Load current or legacy job data into the canonical model."""
    params = {str(key): str(value) for key, value in _mapping(data.get("params")).items()}
    target = str(data.get("target", "")) or params.get("target", "")
    target_type = str(data.get("target_type", "")) or _infer_target_type(target)
    legacy_results = _list_of_dicts(data.get("results"))
    steps = _list_of_dicts(data.get("steps")) or [_normalize_step_entry(entry) for entry in legacy_results]
    summary = _mapping(data.get("summary")) or build_job_summary(
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
    try:
        schema_version = int(data.get("schema_version", 1))
    except (TypeError, ValueError):
        schema_version = 1
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
        schema_version=max(1, schema_version),
    )


def append_result(job: Job, value: dict[str, object]) -> Job:
    """Return a new job containing one normalized execution result."""
    entry = dict(value)
    entry.setdefault("outcome", _step_outcome_from_entry(entry))
    steps = [*job.steps, _normalize_step_entry(entry)]
    results = [*job.results, entry]
    return replace(
        job,
        status=_derive_job_status(steps),
        steps=steps,
        summary=build_job_summary(
            target=job.target,
            target_type=job.target_type,
            steps=steps,
            legacy_results=results,
        ),
        ipintel=_updated_ipintel(job.ipintel, entry),
        results=results,
    )


def step_completion_state(*, tool: str, ok: bool, payload: dict[str, object], outcome: str = "") -> str:
    """Return the normalized completion state for one executed step."""
    return completion_state_for(outcome or classify_result(tool=tool, ok=ok, payload=payload))


def derive_completion_state(statuses: list[str]) -> str:
    """Return the aggregate completion state for a sequence of steps."""
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


def build_job_summary(
    *,
    target: str,
    target_type: str,
    steps: tuple[dict[str, object], ...] | list[dict[str, object]],
    legacy_results: tuple[dict[str, object], ...] | list[dict[str, object]],
) -> dict[str, object]:
    """Aggregate stable report counters from normalized steps."""
    step_list = list(steps)
    summary: dict[str, object] = {
        "step_count": len(step_list),
        "result_count": _count_job_results(step_list, list(legacy_results)),
    }
    if target:
        summary["target"] = target
    if target_type:
        summary["target_type"] = target_type

    counters = {"completed": 0, "negative": 0, "skipped": 0, "warning": 0, "failed": 0}
    open_ports = 0
    filtered_ports = 0
    elapsed_seconds = 0.0
    host_status = ""
    for step in step_list:
        step_status = str(step.get("status", "initialized"))
        outcome = str(step.get("outcome", "done"))
        if step_status == "completed":
            counters[outcome if outcome in {"negative", "skipped"} else "completed"] += 1
        elif step_status == "completed_with_warnings":
            counters["warning"] += 1
        elif step_status == "failed":
            counters["failed"] += 1
        for result_item in step.get("results", []):
            if not isinstance(result_item, dict):
                continue
            state = str(result_item.get("state", "")).lower()
            open_ports += int(state == "open")
            filtered_ports += int(state == "filtered")
        step_summary = _mapping(step.get("summary"))
        if step_summary.get("host_status"):
            host_status = str(step_summary["host_status"])
        if isinstance(step_summary.get("elapsed_seconds"), (int, float)):
            elapsed_seconds += float(step_summary["elapsed_seconds"])

    optional_values = {
        "open_ports": open_ports,
        "filtered_ports": filtered_ports,
        "host_status": host_status,
        "elapsed_seconds": elapsed_seconds,
        "completed_steps": counters["completed"],
        "negative_steps": counters["negative"],
        "skipped_steps": counters["skipped"],
        "warning_steps": counters["warning"],
        "failed_steps": counters["failed"],
    }
    summary.update({key: value for key, value in optional_values.items() if value})
    return summary


def job_summary(job: Job) -> dict[str, object]:
    """Return stored summary data or derive it for a legacy job."""
    return job.summary or build_job_summary(
        target=job.target,
        target_type=job.target_type,
        steps=job.steps,
        legacy_results=job.results,
    )


def normalize_job_id(identifier: str) -> str:
    """Normalize a user-entered job identifier."""
    return identifier.strip().upper().removeprefix("#")


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
    outcome = _step_outcome_from_entry(entry)
    command = payload.get("command", [])
    command_text = " ".join(str(item) for item in command) if isinstance(command, list) else str(command)
    artifacts = entry.get("artifacts", [])
    if not isinstance(artifacts, list):
        artifacts = []
    return {
        "name": _step_name(tool, str(entry.get("action", ""))),
        "status": step_completion_state(
            tool=tool,
            ok=bool(entry.get("ok", False)),
            payload=payload,
            outcome=str(entry.get("outcome", "")),
        ),
        "outcome": outcome,
        "error": str(entry.get("error", "")),
        "command": command_text,
        "summary": summary,
        "results": [item for item in results if isinstance(item, dict)],
        "artifacts": [item for item in artifacts if isinstance(item, dict)],
        "raw_output": str(payload.get("raw_output", "")),
        "provenance": {
            "tool": tool,
            "timestamp": recorded_at,
            "confidence": str(entry.get("confidence", "")),
        },
    }


def _derive_job_status(steps: list[dict[str, object]]) -> str:
    return derive_completion_state([str(step.get("status", "initialized")) for step in steps])


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
    return action or tool or "step"


def _count_job_results(steps: list[dict[str, object]], legacy_results: list[dict[str, object]]) -> int:
    count = sum(1 for step in steps if step.get("results") or step.get("summary") or step.get("error"))
    return count or len(legacy_results)


def _updated_ipintel(current: dict[str, object], entry: dict[str, object]) -> dict[str, object]:
    if str(entry.get("tool", "")) != "ipintel":
        return current
    payload = _mapping(entry.get("payload"))
    keys = (
        "lookup_ip", "asn", "org", "domain", "location", "latency", "vpn_likely",
        "confidence", "jitter", "bandwidth", "mss", "trace", "provider", "raw",
    )
    defaults: dict[str, object] = {"trace": [], "raw": {}}
    return {key: payload.get(key, defaults.get(key, "")) for key in keys}


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
