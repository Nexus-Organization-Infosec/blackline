"""Task executor."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

from blackline.config.tool_loader import get_tool_config
from blackline.core.recon.steps.port_scan import port_state_counts
from blackline.engine.planner import ExecutionPlan, PlanStep
from blackline.tools.intel.yougotmapped import resolve_ipintel
from blackline.tools.dns.resolver import resolve_dns
from blackline.tools.http.client import probe_http
from blackline.tools.network.nmap import NmapRequest, display_command, execute_nmap
from blackline.utils.exec import CommandResult


@dataclass(frozen=True, slots=True)
class StepResult:
    """Outcome of one executed plan step."""

    tool: str
    action: str
    ok: bool
    payload: dict
    error: str = ""


@dataclass(slots=True)
class ExecutionControl:
    """Mutable execution control state for one plan run."""

    cancelled: bool = False
    cancellation_reason: str = ""

    def cancel(self, reason: str = "recon cancelled by user") -> None:
        self.cancelled = True
        self.cancellation_reason = reason


def execute_plan(
    plan: ExecutionPlan,
    *,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    control: ExecutionControl | None = None,
) -> tuple[StepResult, ...]:
    """Execute each step in the given plan."""
    indexed_steps = tuple(enumerate(plan.steps))
    result_slots: list[StepResult | None] = [None] * len(indexed_steps)
    runtime_state: dict[str, object] = {}
    control = control or ExecutionControl()
    for group in _plan_step_groups(indexed_steps):
        if control.cancelled:
            break
        group_results = _execute_step_group(
            group,
            command_executor=command_executor,
            runtime_state=runtime_state,
            control=control,
        )
        for index, result in group_results:
            _update_runtime_state(runtime_state, result)
            result_slots[index] = result
    return tuple(result for result in result_slots if result is not None)


def execute_step(
    step: PlanStep,
    *,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    runtime_state: dict[str, object] | None = None,
) -> StepResult:
    """Execute one supported plan step."""
    timeout_seconds = _step_timeout_seconds(step.tool)

    if step.tool == "dns":
        lookup = _resolve_dns_step(
            step.params.get("host", "") or step.params.get("target", ""),
            command_executor=command_executor,
            timeout_seconds=timeout_seconds,
        )
        payload = {
            "target": step.params.get("target", ""),
            "host": lookup.host,
            "records": dict(lookup.records),
            "resolved_ips": list(lookup.resolved_ips),
            "provider": lookup.provider,
            "raw_output": lookup.raw_output,
            "elapsed_seconds": lookup.elapsed_seconds,
        }
        return StepResult(
            tool=step.tool,
            action=step.action,
            ok=lookup.ok,
            payload=payload,
            error=lookup.error,
        )

    if step.tool == "ipintel":
        runtime_state = runtime_state or {}
        resolved_ips = runtime_state.get("resolved_ips", [])
        if not isinstance(resolved_ips, list):
            resolved_ips = []
        lookup_ip = str(step.params.get("host", ""))
        target_type = str(step.params.get("target_type", "")).lower()
        if target_type != "ip" and resolved_ips:
            lookup_ip = str(resolved_ips[0])
        deep = _to_bool(step.params.get("deep", ""))
        intel = _resolve_ipintel_step(
            str(step.params.get("target", "")),
            lookup_ip=lookup_ip,
            deep=deep,
            timeout_seconds=timeout_seconds,
        )
        payload = {
            "target": step.params.get("target", ""),
            "lookup_ip": intel.lookup_ip,
            "asn": intel.asn,
            "org": intel.org,
            "domain": getattr(intel, "domain", ""),
            "location": intel.location,
            "latency": intel.latency,
            "vpn_likely": intel.vpn_likely,
            "confidence": intel.confidence,
            "jitter": intel.jitter,
            "bandwidth": intel.bandwidth,
            "mss": getattr(intel, "mss", None),
            "trace": list(intel.trace),
            "provider": intel.provider,
            "raw": dict(getattr(intel, "raw", {})),
            "elapsed_seconds": 0.0,
        }
        return StepResult(
            tool=step.tool,
            action=step.action,
            ok=intel.ok,
            payload=payload,
            error=intel.error,
        )

    if step.tool == "http":
        http_result = _probe_http_step(
            str(step.params.get("target", "")),
            mode=step.action,
            host=str(step.params.get("host", "")),
            scheme=str(step.params.get("scheme", "")),
            path=str(step.params.get("path", "")),
            port=str(step.params.get("port", "")),
            host_header=str(step.params.get("host_header", "")),
            timeout=timeout_seconds if timeout_seconds is not None else 10.0,
            command_executor=command_executor,
        )
        payload = {
            "target": step.params.get("target", ""),
            "mode": step.action,
            "provider": http_result.provider,
            "findings": [
                {
                    "url": finding.url,
                    "status_code": finding.status_code,
                    "title": finding.title,
                    "redirect_to": finding.redirect_to,
                    "headers": dict(finding.headers),
                    "ok": finding.ok,
                    "error": finding.error,
                }
                for finding in http_result.findings
            ],
            "elapsed_seconds": http_result.elapsed_seconds,
        }
        return StepResult(
            tool=step.tool,
            action=step.action,
            ok=http_result.ok,
            payload=payload,
            error=http_result.error,
        )

    if step.tool == "nmap":
        execution = _execute_nmap_step(
            NmapRequest(
                target=step.params.get("target", ""),
                ports=step.params.get("ports", ""),
                top_ports=step.params.get("top_ports", ""),
                profile=step.params.get("profile", "default"),
                timing=step.params.get("timing", ""),
                service_detection=_to_bool(step.params.get("service_detection", "")),
                scripts=_to_bool(step.params.get("scripts", "")),
                os_detection=_to_bool(step.params.get("os_detection", "")),
            ),
            executor=command_executor,
            timeout_seconds=timeout_seconds,
        )
        payload = {
            "provider": "nmap",
            "command": list(display_command(execution.command)),
            "target": execution.parsed.target,
            "host_status": execution.parsed.host_status,
            "raw_output": execution.parsed.raw_output,
            "ports": [
                {
                    "port": port.port,
                    "protocol": port.protocol,
                    "state": port.state,
                    "service": port.service,
                    **({"version": port.version} if port.version else {}),
                }
                for port in execution.parsed.ports
            ],
            "warnings": list(execution.parsed.warnings),
            "system": {
                "device": getattr(execution.parsed, "device_type", ""),
                "os": getattr(execution.parsed, "operating_system", ""),
                "kernel": getattr(execution.parsed, "kernel", ""),
                "cpe": getattr(execution.parsed, "cpe", ""),
                "distance": getattr(execution.parsed, "distance", ""),
            },
        }
        counts = port_state_counts(payload["ports"])
        return StepResult(
            tool=step.tool,
            action=step.action,
            ok=execution.ok,
            payload={
                **payload,
                "open_ports": counts["open"],
                "filtered_ports": counts["filtered"],
                "interesting_ports": counts["interesting"],
                "elapsed_seconds": execution.elapsed_seconds,
            },
            error=execution.error or execution.stderr,
        )

    return StepResult(tool=step.tool, action=step.action, ok=False, payload={}, error="unsupported tool")


def _to_bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _update_runtime_state(runtime_state: dict[str, object], result: StepResult) -> None:
    if result.tool == "dns":
        resolved_ips = result.payload.get("resolved_ips", [])
        if isinstance(resolved_ips, list):
            runtime_state["resolved_ips"] = list(resolved_ips)


def _step_timeout_seconds(tool: str) -> float | None:
    """Return the configured timeout for one recon step tool."""
    config = get_tool_config("recon")
    execution_control = config.get("execution_control", {})
    if not isinstance(execution_control, dict):
        return None
    timeouts = execution_control.get("timeouts", {})
    if not isinstance(timeouts, dict):
        return None

    key_map = {
        "dns": "dns_seconds",
        "ipintel": "ipintel_seconds",
        "http": "http_seconds",
        "nmap": "port_scan_seconds",
    }
    raw = timeouts.get(key_map.get(tool, ""))
    try:
        if raw in {None, "", 0, "0"}:
            return None
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _plan_step_groups(indexed_steps: tuple[tuple[int, PlanStep], ...]) -> list[tuple[tuple[int, PlanStep], ...]]:
    """Group plan steps into deterministic execution waves."""
    groups: dict[int, list[tuple[int, PlanStep]]] = {}
    for indexed_step in indexed_steps:
        group_id = _effective_execution_group(indexed_step[1])
        groups.setdefault(group_id, []).append(indexed_step)
    return [tuple(groups[group_id]) for group_id in sorted(groups)]


def _execute_step_group(
    steps: tuple[tuple[int, PlanStep], ...],
    *,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None,
    runtime_state: dict[str, object],
    control: ExecutionControl,
) -> list[tuple[int, StepResult]]:
    """Execute one deterministic step wave, in parallel when safe."""
    if len(steps) <= 1:
        index, step = steps[0]
        try:
            return [(index, execute_step(step, command_executor=command_executor, runtime_state=runtime_state))]
        except KeyboardInterrupt:
            control.cancel()
            return []

    base_state = dict(runtime_state)
    futures: list[tuple[int, Future[StepResult]]] = []
    with ThreadPoolExecutor(max_workers=len(steps)) as pool:
        for index, step in steps:
            futures.append(
                (
                    index,
                    pool.submit(
                    execute_step,
                    step,
                    command_executor=command_executor,
                    runtime_state=dict(base_state),
                    ),
                )
            )

        results: list[tuple[int, StepResult]] = []
        try:
            for index, future in futures:
                results.append((index, future.result()))
        except KeyboardInterrupt:
            control.cancel()
            for _, future in futures:
                future.cancel()
            return []
    return results


def _effective_execution_group(step: PlanStep) -> int:
    """Infer a safe execution group, even for manually-constructed plan steps."""
    if step.execution_group:
        return step.execution_group

    target_type = str(step.params.get("target_type", "")).strip().lower()
    if step.tool == "ipintel":
        return 0 if target_type == "ip" else 1
    if step.tool == "nmap":
        return 1 if target_type == "ip" else 2
    return 0


def _resolve_dns_step(
    host: str,
    *,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None,
    timeout_seconds: float | None,
):
    try:
        return resolve_dns(host, command_executor=command_executor, timeout_seconds=timeout_seconds)
    except TypeError:
        return resolve_dns(host, command_executor=command_executor)


def _resolve_ipintel_step(
    target: str,
    *,
    lookup_ip: str,
    deep: bool,
    timeout_seconds: float | None,
):
    try:
        return resolve_ipintel(target, lookup_ip=lookup_ip, deep=deep, timeout_seconds=timeout_seconds)
    except TypeError:
        return resolve_ipintel(target, lookup_ip=lookup_ip, deep=deep)


def _probe_http_step(
    target: str,
    *,
    mode: str,
    host: str,
    scheme: str,
    path: str,
    port: str,
    host_header: str,
    timeout: float,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None,
):
    try:
        return probe_http(
            target,
            mode=mode,
            host=host,
            scheme=scheme,
            path=path,
            port=port,
            host_header=host_header,
            timeout=timeout,
            command_executor=command_executor,
        )
    except TypeError:
        return probe_http(
            target,
            mode=mode,
            host=host,
            scheme=scheme,
            path=path,
            port=port,
            host_header=host_header,
            command_executor=command_executor,
        )


def _execute_nmap_step(
    request: NmapRequest,
    *,
    executor: Callable[[tuple[str, ...]], CommandResult] | None,
    timeout_seconds: float | None,
):
    try:
        return execute_nmap(request, executor=executor, timeout_seconds=timeout_seconds)
    except TypeError:
        return execute_nmap(request, executor=executor)
