"""Engine runner."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable

from blackline.core.recon.pipeline import build_recon_pipeline
from blackline.core.recon.outcomes import outcome_is_success
from blackline.engine.executor import ExecutionControl, ExecutionProgress, StepResult, execute_plan
from blackline.engine.planner import ExecutionPlan, build_essential_recon_plan, build_plan
from blackline.engine.context import ExecutionContext
from blackline.engine.session import EngineSession
from blackline.utils.exec import CommandResult


@dataclass(frozen=True, slots=True)
class RunResult:
    """Top-level engine run result."""

    context: ExecutionContext
    plan: ExecutionPlan
    results: tuple[StepResult, ...]
    cancelled: bool = False
    cancellation_reason: str = ""
    rounds: tuple[object, ...] = ()

    @property
    def ok(self) -> bool:
        return (not self.cancelled) and all(outcome_is_success(result.outcome) for result in self.results)


def run_expression(
    expression: str,
    *,
    session: EngineSession | None = None,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    plan_callback: Callable[[ExecutionPlan], None] | None = None,
    progress_callback: Callable[[ExecutionProgress], None] | None = None,
    vector_callback: Callable[[object], None] | None = None,
) -> RunResult:
    """Parse, plan, and execute one expression."""
    session = session or EngineSession()
    context = parse_expression(expression, job_id=session.active_job)
    if context.module == "recon" and context.params.get("strategy", "").strip().lower() == "auto":
        return _run_recon_iteratively(
            context,
            expression=expression,
            session=session,
            command_executor=command_executor,
            plan_callback=plan_callback,
            progress_callback=progress_callback,
            vector_callback=vector_callback,
        )
    plan = build_plan(context)
    if plan_callback is not None:
        plan_callback(plan)
    control = ExecutionControl()
    results = execute_plan(
        plan,
        command_executor=command_executor,
        control=control,
        progress_callback=progress_callback,
    )
    session.runs.append(expression)
    return RunResult(
        context=context,
        plan=plan,
        results=results,
        cancelled=control.cancelled,
        cancellation_reason=control.cancellation_reason,
    )


def _run_recon_iteratively(
    context: ExecutionContext,
    *,
    expression: str,
    session: EngineSession,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None,
    plan_callback: Callable[[ExecutionPlan], None] | None,
    progress_callback: Callable[[ExecutionProgress], None] | None,
    vector_callback: Callable[[object], None] | None,
) -> RunResult:
    """Execute essential discovery, then let Vector create bounded follow-ups."""
    from blackline.core.recon.vector_adapter import (
        InvestigationRound,
        create_recon_vector,
        execute_followup_plan,
        recon_round_limit,
        observations_from_results,
    )

    essential_plan = build_essential_recon_plan(context)
    if plan_callback is not None:
        plan_callback(essential_plan)
    control = ExecutionControl()
    all_steps = list(essential_plan.steps)
    all_results = list(
        execute_plan(
            essential_plan,
            command_executor=command_executor,
            control=control,
            progress_callback=progress_callback,
        )
    )
    vector = create_recon_vector(context)
    rounds: list[InvestigationRound] = []
    strategy = context.params.get("strategy", "balanced").strip().lower() or "balanced"
    limit = recon_round_limit(strategy)
    round_number = 1

    while not control.cancelled and round_number <= limit:
        evidence = observations_from_results(all_results[-len(essential_plan.steps) :] if round_number == 1 else latest_results, fallback_host=context.normalized_target.host if context.normalized_target else context.params.get("target", ""))
        decision = vector.observe(evidence)
        rounds.append(InvestigationRound(round_number, round_number == 1, tuple(all_results[-len(essential_plan.steps) :] if round_number == 1 else latest_results), decision))
        if vector_callback is not None:
            vector_callback(rounds[-1])
        if not decision.selected:
            break

        followup_plan = execute_followup_plan(context, decision)
        for candidate in decision.selected:
            vector.mark_completed(candidate)
        if not followup_plan.steps:
            break
        if plan_callback is not None:
            plan_callback(followup_plan)
        latest_results = execute_plan(
            followup_plan,
            command_executor=command_executor,
            control=control,
            progress_callback=progress_callback,
        )
        all_steps.extend(followup_plan.steps)
        all_results.extend(latest_results)
        round_number += 1

    session.runs.append(expression)
    aggregate = ExecutionPlan(context=context, steps=tuple(all_steps), pipeline=essential_plan.pipeline)
    return RunResult(
        context=context,
        plan=aggregate,
        results=tuple(all_results),
        cancelled=control.cancelled,
        cancellation_reason=control.cancellation_reason,
        rounds=tuple(rounds),
    )


def parse_expression(expression: str, *, job_id: str = "") -> ExecutionContext:
    """Parse a module[key=value] expression into execution context."""
    stripped = normalize_expression(expression)
    if not stripped:
        return ExecutionContext(expression=expression, module="", params={}, job_id=job_id)

    if "[" not in stripped:
        return ExecutionContext(expression=expression, module=stripped, params={}, job_id=job_id)

    if not stripped.endswith("]"):
        return ExecutionContext(expression=expression, module=stripped, params={}, job_id=job_id)

    module, raw_params = stripped.split("[", 1)
    params: dict[str, str] = {}
    raw_params = raw_params[:-1].strip()
    if raw_params:
        for pair in raw_params.split(","):
            if "=" not in pair:
                continue
            key, value = pair.split("=", 1)
            params[key.strip()] = value.strip()

    normalized_target = None
    clean_module = module.strip()
    if clean_module == "recon" and params.get("target"):
        try:
            normalized_target = build_recon_pipeline(params["target"]).target
        except ValueError:
            normalized_target = None

    return ExecutionContext(
        expression=expression,
        module=clean_module,
        params=params,
        job_id=job_id,
        normalized_target=normalized_target,
    )


def normalize_expression(expression: str) -> str:
    """Normalize module expressions to be tolerant of spacing and newlines."""
    normalized = " ".join(expression.strip().split())
    normalized = re.sub(r"\s*\[\s*", "[", normalized)
    normalized = re.sub(r"\s*,\s*", ", ", normalized)
    normalized = re.sub(r"\s*=\s*", "=", normalized)
    normalized = re.sub(r"\s*\]\s*", "]", normalized)
    return normalized
