"""Task executor."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from blackline.engine.planner import ExecutionPlan, PlanStep
from blackline.tools.recon.nmap import NmapRequest, execute_nmap
from blackline.utils.exec import CommandResult


@dataclass(frozen=True, slots=True)
class StepResult:
    """Outcome of one executed plan step."""

    tool: str
    action: str
    ok: bool
    payload: dict
    error: str = ""


def execute_plan(
    plan: ExecutionPlan,
    *,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
) -> tuple[StepResult, ...]:
    """Execute each step in the given plan."""
    results: list[StepResult] = []
    for step in plan.steps:
        results.append(execute_step(step, command_executor=command_executor))
    return tuple(results)


def execute_step(
    step: PlanStep,
    *,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
) -> StepResult:
    """Execute one supported plan step."""
    if step.tool == "nmap":
        execution = execute_nmap(
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
        )
        payload = {
            "command": list(execution.command),
            "target": execution.parsed.target,
            "host_status": execution.parsed.host_status,
            "raw_output": execution.parsed.raw_output,
            "ports": [
                {
                    "port": port.port,
                    "protocol": port.protocol,
                    "state": port.state,
                    "service": port.service,
                }
                for port in execution.parsed.ports
            ],
            "warnings": list(execution.parsed.warnings),
        }
        return StepResult(
            tool=step.tool,
            action=step.action,
            ok=execution.ok,
            payload={**payload, "elapsed_seconds": execution.elapsed_seconds},
            error=execution.error or execution.stderr,
        )

    return StepResult(tool=step.tool, action=step.action, ok=False, payload={}, error="unsupported tool")


def _to_bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
