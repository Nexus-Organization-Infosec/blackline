"""Task planner."""

from __future__ import annotations

from dataclasses import dataclass, field

from blackline.engine.state.context import ExecutionContext


@dataclass(frozen=True, slots=True)
class PlanStep:
    """One executable step in a plan."""

    tool: str
    action: str
    params: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """Small linear execution plan."""

    context: ExecutionContext
    steps: tuple[PlanStep, ...]


def build_plan(context: ExecutionContext) -> ExecutionPlan:
    """Build a linear plan for the current context."""
    if context.module == "recon":
        return ExecutionPlan(
            context=context,
            steps=(
                PlanStep(
                    tool="nmap",
                    action="scan",
                    params={
                        "target": context.params.get("target", ""),
                        "ports": context.params.get("ports", "1-1024"),
                        "top_ports": context.params.get("top_ports", ""),
                        "profile": _recon_profile(context.params),
                        "timing": _recon_timing(context.params),
                        "service_detection": _recon_service_detection(context.params),
                        "scripts": _recon_scripts(context.params),
                        "os_detection": _recon_os_detection(context.params),
                    },
                ),
            ),
        )

    return ExecutionPlan(context=context, steps=())


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
