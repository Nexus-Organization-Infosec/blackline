"""Task planner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from blackline.core.recon import ReconPipeline, build_recon_pipeline
from blackline.core.recon.models import ReconStep
from blackline.core.recon.scan_policy import nmap_policy_params
from blackline.engine.context import ExecutionContext

if TYPE_CHECKING:
    from blackline.vector.candidate import Candidate


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
                if step.tool in {"dns", "subfinder", "ipintel", "http", "httpx", "fingerprint", "whatweb", "katana", "tls", "sslyze", "rdap", "rpcinfo", "naabu", "nmap"}
            ),
            pipeline=pipeline,
        )

    return ExecutionPlan(context=context, steps=())


def build_essential_recon_plan(context: ExecutionContext) -> ExecutionPlan:
    """Build only the orientation work required before Vector can decide more."""
    if context.module != "recon":
        return build_plan(context)
    pipeline = build_recon_pipeline(context.params.get("target", ""), params=context.params)
    essential_tools = {"dns", "naabu", "nmap"}
    if pipeline.target.target_type == "url":
        essential_tools.add("http")
    steps = tuple(
        _plan_step_from_recon_step(step, context.params)
        for step in pipeline.steps
        if step.tool in essential_tools
    )
    return ExecutionPlan(context=context, steps=steps, pipeline=pipeline)


def build_followup_plan(context: ExecutionContext, candidates: tuple[Candidate, ...]) -> ExecutionPlan:
    """Translate Vector capability intents into concrete tool requests.

    Vector provides the capability and endpoint. This adapter owns the current
    tool mapping, so Vector never learns binary flags or request syntax.
    """
    if context.module != "recon" or context.normalized_target is None:
        return ExecutionPlan(context=context, steps=())
    target = context.normalized_target
    steps: list[PlanStep] = []
    for candidate in candidates:
        intent = candidate.intent
        if intent.verb == "collect" and intent.subject.startswith("network_intelligence"):
            steps.append(
                PlanStep(
                    tool="ipintel",
                    action="network_intelligence",
                    params={
                        "target": context.params.get("target", ""),
                        "host": target.host,
                        "target_type": target.target_type,
                        "deep": "true" if context.params.get("strategy", "") == "deep" else "false",
                    },
                    execution_group=0,
                )
            )
            continue
        endpoint = _endpoint(candidate.target, fallback=target.host)
        if endpoint is None:
            continue
        host, port = endpoint
        if intent.verb == "probe" and intent.subject in {"http", "https"}:
            steps.append(
                PlanStep(
                    tool="httpx",
                    action="httpx_probe",
                    params={
                        "target": context.params.get("target", ""),
                        "host": host,
                        "port": str(port),
                        "scheme": intent.subject,
                        "path": target.path,
                        "target_type": target.target_type,
                    },
                    execution_group=0,
                )
            )
        elif intent.verb == "fingerprint" and intent.subject in {"http", "https"}:
            steps.append(
                PlanStep(
                    tool="fingerprint",
                    action="web_fingerprint",
                    params={
                        "target": context.params.get("target", ""),
                        "host": host,
                        "port": str(port),
                        "scheme": intent.subject,
                        "path": target.path,
                        "target_type": target.target_type,
                    },
                    execution_group=1,
                )
            )
        elif intent.verb == "inspect" and intent.subject == "tls":
            steps.append(
                PlanStep(
                    tool="tls",
                    action="tls_inspection",
                    params={
                        "target": context.params.get("target", ""),
                        "host": host,
                        "port": str(port),
                        "server_name": target.host if target.target_type != "ip" else "",
                    },
                    execution_group=0,
                )
            )
    return ExecutionPlan(context=context, steps=tuple(steps))


def _endpoint(value: str, *, fallback: str) -> tuple[str, int] | None:
    """Parse Vector's compact endpoint identity without imposing tool syntax."""
    host, separator, raw_port = value.rpartition(":")
    if not separator:
        return None
    try:
        port = int(raw_port)
    except ValueError:
        return None
    if not host:
        host = fallback
    return (host, port) if 1 <= port <= 65535 else None


def _plan_step_from_recon_step(step: ReconStep, params: dict[str, str]) -> PlanStep:
    if step.tool == "dns":
        return PlanStep(
            tool="dns",
            action=step.name,
            params={key: str(value) for key, value in step.inputs.items()},
            execution_group=_execution_group(step),
        )

    if step.tool == "subfinder":
        return PlanStep(
            tool="subfinder",
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

    if step.tool == "httpx":
        return PlanStep(
            tool="httpx",
            action=step.name,
            params={key: str(value) for key, value in step.inputs.items()},
            execution_group=_execution_group(step),
        )

    if step.tool == "whatweb":
        return PlanStep(
            tool="whatweb",
            action=step.name,
            params={key: str(value) for key, value in step.inputs.items()},
            execution_group=_execution_group(step),
        )

    if step.tool == "katana":
        return PlanStep(
            tool="katana",
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

    if step.tool == "rpcinfo":
        return PlanStep(
            tool="rpcinfo",
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

    if step.tool == "sslyze":
        return PlanStep(
            tool="sslyze",
            action=step.name,
            params={key: str(value) for key, value in step.inputs.items()},
            execution_group=_execution_group(step),
        )

    if step.tool == "naabu":
        scan_params = nmap_policy_params(params)
        return PlanStep(
            tool="naabu",
            action=step.name,
            params={
                "target": str(step.inputs.get("target", "")),
                "target_type": str(step.inputs.get("target_type", "")),
                "ports": str(step.inputs.get("ports", "")) or scan_params["ports"],
                "top_ports": str(step.inputs.get("top_ports", "")) or scan_params["top_ports"],
            },
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
    if step.tool in {"dns", "subfinder", "http", "httpx", "tls"}:
        return 0
    if step.tool == "naabu":
        return 0
    if step.tool == "sslyze":
        return 1
    if step.tool == "rpcinfo":
        return 1
    if step.tool in {"fingerprint", "whatweb", "katana"}:
        return 1
    if step.tool == "rdap":
        return 2
    return 0
