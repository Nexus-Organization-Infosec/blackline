"""Privilege decisions for planned reconnaissance work."""

from __future__ import annotations

from blackline.engine.planner import PlanStep, build_plan
from blackline.engine.runner import parse_expression
from blackline.tools.network.nmap import NmapRequest, requires_sudo_for_request


def requires_elevation(expression: str) -> bool:
    """Return whether executing a valid recon expression needs elevation.

    This deliberately lives beside recon planning rather than in the shell: the
    caller only needs a yes/no privilege decision, while tool-specific request
    construction remains an implementation detail here.
    """
    context = parse_expression(expression)
    plan = build_plan(context)
    return any(
        step.tool == "nmap" and requires_sudo_for_request(_nmap_request_from_step(step))
        for step in plan.steps
    )


def _nmap_request_from_step(step: PlanStep) -> NmapRequest:
    """Build an nmap request from one planned nmap step."""
    return NmapRequest(
        target=str(step.params.get("target", "")),
        ports=str(step.params.get("ports", "")),
        top_ports=str(step.params.get("top_ports", "")),
        profile=str(step.params.get("profile", "default") or "default"),
        timing=str(step.params.get("timing", "")),
        service_detection=_truthy(step.params.get("service_detection", "")),
        scripts=_truthy(step.params.get("scripts", "")),
        os_detection=_truthy(step.params.get("os_detection", "")),
        use_default_timing=_truthy(step.params.get("use_default_timing", "true")),
    )


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
