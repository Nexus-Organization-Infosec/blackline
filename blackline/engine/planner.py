"""Task planner."""

from __future__ import annotations

from dataclasses import dataclass, field

from blackline.core.recon import ReconPipeline, build_recon_pipeline
from blackline.core.recon.models import ReconStep
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
                if step.tool in {"dns", "ipintel", "http", "nmap"}
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

    return PlanStep(
        tool=step.tool,
        action=step.name,
        params={
            "target": str(step.inputs.get("target", "")),
            "ports": str(step.inputs.get("ports", "1-1024")),
            "top_ports": str(step.inputs.get("top_ports", "")),
            "profile": _recon_profile(params),
            "timing": _recon_timing(params),
            "service_detection": _recon_service_detection(params),
            "scripts": _recon_scripts(params),
            "os_detection": _recon_os_detection(params),
        },
        execution_group=_execution_group(step),
    )


def _recon_profile(params: dict[str, str]) -> str:
    profile = params.get("profile", "")
    if profile:
        return profile

    strategy = params.get("strategy", "").strip().lower()
    transport = params.get("transport", "").strip().lower()
    if strategy == "quiet":
        return "stealth"
    if strategy == "fast":
        return "service"
    if strategy == "deep":
        return "aggressive"
    if strategy == "udp" or transport == "udp":
        return "udp"
    return "default"


def _recon_timing(params: dict[str, str]) -> str:
    timing = params.get("timing", "")
    if timing:
        return timing

    speed = params.get("speed", "").strip().lower()
    mapping = {
        "low": "T2",
        "normal": "T3",
        "high": "T4",
        "aggressive": "T5",
    }
    return mapping.get(speed, "")


def _recon_service_detection(params: dict[str, str]) -> str:
    if "service" in params:
        return params.get("service", "")
    if "service_detection" in params:
        return params.get("service_detection", "")

    probe = params.get("probe", "").strip().lower()
    return "true" if probe in {"service", "script", "fingerprint"} else ""


def _recon_scripts(params: dict[str, str]) -> str:
    if "scripts" in params:
        return params.get("scripts", "")

    probe = params.get("probe", "").strip().lower()
    return "true" if probe in {"script", "fingerprint"} else ""


def _recon_os_detection(params: dict[str, str]) -> str:
    if "os" in params:
        return params.get("os", "")
    if "os_detection" in params:
        return params.get("os_detection", "")

    probe = params.get("probe", "").strip().lower()
    return "true" if probe == "fingerprint" else ""


def _execution_group(step: ReconStep) -> int:
    """Return the deterministic execution wave for one recon step."""
    target_type = str(step.inputs.get("target_type", "")).strip().lower()
    if step.tool == "nmap":
        return 1 if target_type == "ip" else 2
    if step.tool == "ipintel":
        return 0 if target_type == "ip" else 1
    if step.tool in {"dns", "http"}:
        return 0
    return 0
