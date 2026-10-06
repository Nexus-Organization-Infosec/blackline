"""Task planner."""

from __future__ import annotations

from dataclasses import replace
from collections.abc import Iterable
from typing import TYPE_CHECKING

from blackline.core.recon import ReconPipeline, build_recon_pipeline
from blackline.core.recon.models import ReconStep
from blackline.core.recon.scan_policy import nmap_policy_params
from blackline.core.recon.tool_registry import get_recon_tool
from blackline.engine.context import ExecutionContext
from blackline.engine.models import ExecutionPlan, PlanStep, StepDependency, StepId

if TYPE_CHECKING:
    from blackline.vector.candidate import Candidate


def build_plan(context: ExecutionContext) -> ExecutionPlan:
    """Build a linear plan for the current context."""
    if context.module == "recon":
        pipeline = build_recon_pipeline(context.params.get("target", ""), params=context.params)
        return _execution_plan(
            context,
            (
                _plan_step_from_recon_step(step, context.params)
                for step in pipeline.steps
                if _is_plannable_provider(step.tool)
            ),
            pipeline=pipeline,
            reason=f"selected by the {context.params.get('strategy', 'balanced') or 'balanced'} recon profile",
        )

    return _execution_plan(context, ())


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
    return _execution_plan(
        context,
        steps,
        pipeline=pipeline,
        reason="required for adaptive recon orientation",
    )


def build_followup_plan(context: ExecutionContext, candidates: tuple[Candidate, ...]) -> ExecutionPlan:
    """Translate Vector capability intents into concrete tool requests.

    Vector provides the capability and endpoint. This adapter owns the current
    tool mapping, so Vector never learns binary flags or request syntax.
    """
    if context.module != "recon" or context.normalized_target is None:
        return _execution_plan(context, ())
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
        if intent.verb == "discover" and intent.subject == "http_services":
            steps.append(
                PlanStep(
                    tool="httpx",
                    action="discover_http_services",
                    params={
                        "target": context.params.get("target", ""),
                        "host": host,
                        "port": str(port),
                        "target_type": target.target_type,
                    },
                    execution_group=0,
                )
            )
            continue
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
        elif intent.verb == "inspect" and intent.subject == "smb":
            steps.append(
                PlanStep(
                    tool="smbclient",
                    action="smb_share_enumeration",
                    params={
                        "target": context.params.get("target", ""),
                        "host": host,
                        "port": str(port),
                        "target_type": target.target_type,
                    },
                    execution_group=0,
                )
            )
    return _execution_plan(context, steps, reason="selected by adaptive recon planning")


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
    if step.tool not in {"naabu", "nmap"}:
        return PlanStep(
            tool=step.tool,
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


def _execution_plan(
    context: ExecutionContext,
    steps: Iterable[PlanStep],
    *,
    pipeline: ReconPipeline | None = None,
    reason: str = "",
) -> ExecutionPlan:
    """Attach deterministic identities and capabilities to planned steps."""
    materialized = tuple(steps)
    occurrences: dict[tuple[str, str], int] = {}
    planned: list[PlanStep] = []
    for step in materialized:
        if not isinstance(step, PlanStep):
            raise TypeError("execution plans may contain only PlanStep values")
        key = (step.tool, step.action)
        occurrences[key] = occurrences.get(key, 0) + 1
        capability = _capability_for(step.tool, step.action)
        provider = get_recon_tool(step.tool)
        planned.append(
            replace(
                step,
                id=step.id or StepId(f"{step.tool}.{step.action}.{occurrences[key]}"),
                capability=step.capability or capability,
                consumes=step.consumes or (provider.consumes if provider else ()),
                produces=step.produces or (provider.produces if provider else ()),
                reason=step.reason or reason,
                timeout_seconds=step.timeout_seconds if step.timeout_seconds is not None else (provider.timeout_seconds if provider else None),
            )
        )
    planned = _attach_wave_dependencies(planned)
    plan = ExecutionPlan(context=context, steps=tuple(planned), pipeline=pipeline)
    plan.validate()
    return plan


def _capability_for(tool: str, action: str) -> str:
    if tool == "httpx":
        return "http.discover" if action == "discover_http_services" else "http.probe"
    provider = get_recon_tool(tool)
    return provider.capability if provider else tool


def _attach_wave_dependencies(steps: list[PlanStep]) -> list[PlanStep]:
    """Express current execution-wave ordering as explicit DAG edges."""
    planned: list[PlanStep] = []
    for step in steps:
        if step.depends_on or step.execution_group <= 0:
            planned.append(step)
            continue
        dependencies = tuple(
            StepDependency(
                StepId(upstream.identity),
                required_artifacts=tuple(sorted(set(step.consumes) & set(upstream.produces))),
                optional=True,
            )
            for upstream in steps
            if upstream.execution_group < step.execution_group
        )
        planned.append(replace(step, depends_on=dependencies))
    return planned


def _is_plannable_provider(name: str) -> bool:
    provider = get_recon_tool(name)
    return bool(provider and provider.lifecycle == "active" and provider.handler)


def _execution_group(step: ReconStep) -> int:
    """Return the deterministic execution wave for one recon step."""
    target_type = str(step.inputs.get("target_type", "")).strip().lower()
    if step.tool == "nmap":
        return 1 if target_type == "ip" else 2
    if step.tool == "ipintel":
        return 0 if target_type == "ip" else 1
    if step.tool in {"dns", "subfinder", "http", "tls"}:
        return 0
    if step.tool == "httpx":
        # Protocol discovery consumes the open endpoints produced by Naabu/Nmap.
        return 3
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
