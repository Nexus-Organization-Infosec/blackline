"""Pipeline orchestration."""

from __future__ import annotations

from dataclasses import dataclass

from blackline.engine.executor import StepResult, execute_plan
from blackline.engine.planner import ExecutionPlan, build_plan
from blackline.engine.context import ExecutionContext


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Combined planning and execution result."""

    plan: ExecutionPlan
    results: tuple[StepResult, ...]


def run_pipeline(context: ExecutionContext) -> PipelineResult:
    """Build and execute the plan for one context."""
    plan = build_plan(context)
    return PipelineResult(plan=plan, results=execute_plan(plan))
