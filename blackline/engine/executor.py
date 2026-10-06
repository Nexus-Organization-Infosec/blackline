"""Registered step dispatch and the public plan-execution facade."""

from __future__ import annotations

from typing import Callable

from blackline.core.artifacts import ArtifactStore
from blackline.core.recon.tool_registry import get_recon_tool
from blackline.engine.events import EventEmitter, ExecutionEventCallback, command_event_callback
from blackline.engine.handlers import HandlerRegistry, default_handler_registry
from blackline.engine.handlers.base import HandlerContext
from blackline.engine.models import ExecutionPlan, PlanStep, StepResult
from blackline.engine.scheduler import (
    ExecutionControl,
    ExecutionProgress,
    SchedulerOptions,
    schedule_plan,
)
from blackline.utils.exec import CommandResult, CommandTraceCallback, trace_commands

_DEFAULT_HANDLERS = default_handler_registry()


def execute_plan(
    plan: ExecutionPlan,
    *,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    control: ExecutionControl | None = None,
    progress_callback: Callable[[ExecutionProgress], None] | None = None,
    command_callback: CommandTraceCallback | None = None,
    event_callback: ExecutionEventCallback | None = None,
    handler_registry: HandlerRegistry | None = None,
    scheduler_options: SchedulerOptions | None = None,
) -> tuple[StepResult, ...]:
    """Execute a plan through bounded scheduling and registered handlers."""
    plan.validate()
    control = control or ExecutionControl()
    registry = handler_registry or _DEFAULT_HANDLERS
    artifacts = ArtifactStore()
    emitter = EventEmitter(event_callback, job_id=str(getattr(plan.context, "job_id", "")))

    def dispatch(step: PlanStep, evidence: ArtifactStore) -> StepResult:
        callback = command_event_callback(emitter, step, command_callback)
        with trace_commands(callback):
            return execute_step(
                step,
                command_executor=command_executor,
                artifact_store=evidence,
                handler_registry=registry,
            )

    return schedule_plan(
        plan,
        dispatch,
        control=control,
        artifact_store=artifacts,
        emitter=emitter,
        options=scheduler_options or SchedulerOptions(),
        progress_callback=progress_callback,
    )


def execute_step(
    step: PlanStep,
    *,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    artifact_store: ArtifactStore | None = None,
    handler_registry: HandlerRegistry | None = None,
) -> StepResult:
    """Resolve and execute one provider without tool-specific branching."""
    evidence = artifact_store if artifact_store is not None else ArtifactStore()
    missing_artifacts = sorted(
        {
            kind
            for dependency in step.depends_on
            if not dependency.optional
            for kind in dependency.required_artifacts
            if not evidence.has(kind)
        }
    )
    if missing_artifacts:
        reason = f"missing required artifacts: {', '.join(missing_artifacts)}"
        return StepResult(
            step.tool,
            step.action,
            False,
            {"skipped": True, "skip_reason": reason},
            reason,
        )
    provider = get_recon_tool(step.tool)
    handler_name = provider.handler if provider is not None else step.tool
    handler = (handler_registry or _DEFAULT_HANDLERS).resolve(handler_name)
    if handler is None:
        return StepResult(step.tool, step.action, False, {}, f"unsupported tool: {step.tool}")
    return handler(step, HandlerContext(command_executor=command_executor, artifacts=evidence))
