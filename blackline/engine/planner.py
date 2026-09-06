"""Task planner."""

from __future__ import annotations

from dataclasses import dataclass, field

from blackline.core.recon import ReconPipeline, build_recon_pipeline
from blackline.core.recon.models import ReconStep
from blackline.core.recon.scan_policy import nmap_policy_params
from blackline.engine.context import ExecutionContext


@dataclass(frozen=True, slots=True)
class PlanStep:
    """One executable step in a plan."""

    tool: str
    action: str
    params: dict[str, str] = field(default_factory=dict)
    execution_group: int = 0


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """Small linear execution plan."""

    context: ExecutionContext
    steps: tuple[PlanStep, ...]
    pipeline: ReconPipeline | None = None


def build_plan(context: ExecutionContext) -> ExecutionPlan:
    """Build a linear plan for the current context."""
    if context.module == "recon":
        pipeline = build_recon_pipeline(context.params.get("target", ""), params=context.params)
        return ExecutionPlan(
            context=context,
            steps=tuple(
                _plan_step_from_recon_step(step, context.params)
                for step in pipeline.steps
                if step.tool in {"dns", "ipintel", "http", "fingerprint", "tls", "rdap", "nmap"}
            ),
            pipeline=pipeline,
        )

    return ExecutionPlan(context=context, steps=())


def _plan_step_from_recon_step(step: ReconStep, params: dict[str, str]) -> PlanStep:
    if step.tool == "dns":
        return PlanStep(
            tool="dns",
            action=step.name,
            params={key: str(value) for key, value in step.inputs.items()},
            execution_group=_execution_group(step),
        )

    if step.tool == "ipintel":
        return PlanStep(
            tool="ipintel",
            action=step.name,
            params={key: str(value) for key, value in step.inputs.items()},
            execution_group=_execution_group(step),
        )

    if step.tool == "http":
        return PlanStep(
            tool="http",
            action=step.name,
            params={key: str(value) for key, value in step.inputs.items()},
            execution_group=_execution_group(step),
        )

    if step.tool == "fingerprint":
        return PlanStep(
            tool="fingerprint",
            action=step.name,
            params={key: str(value) for key, value in step.inputs.items()},
            execution_group=_execution_group(step),
        )

    if step.tool == "rdap":
        return PlanStep(
            tool="rdap",
            action=step.name,
            params={key: str(value) for key, value in step.inputs.items()},
            execution_group=_execution_group(step),
        )

    if step.tool == "tls":
        return PlanStep(
            tool="tls",
            action=step.name,
            params={key: str(value) for key, value in step.inputs.items()},
            execution_group=_execution_group(step),
        )

    scan_params = nmap_policy_params(params)
    return PlanStep(
        tool=step.tool,
        action=step.name,
        params={
            "target": str(step.inputs.get("target", "")),
            "ports": str(step.inputs.get("ports", "")) or scan_params["ports"],
            "top_ports": str(step.inputs.get("top_ports", "")) or scan_params["top_ports"],
            "profile": scan_params["profile"],
            "timing": scan_params["timing"],
            "service_detection": scan_params["service_detection"],
            "scripts": scan_params["scripts"],
            "os_detection": scan_params["os_detection"],
            "use_default_timing": scan_params["use_default_timing"],
        },
        execution_group=_execution_group(step),
    )


def _execution_group(step: ReconStep) -> int:
    """Return the deterministic execution wave for one recon step."""
    target_type = str(step.inputs.get("target_type", "")).strip().lower()
    if step.tool == "nmap":
        return 1 if target_type == "ip" else 2
    if step.tool == "ipintel":
        return 0 if target_type == "ip" else 1
    if step.tool in {"dns", "http", "tls"}:
        return 0
    if step.tool == "fingerprint":
        return 1
    if step.tool == "rdap":
        return 2
    return 0
