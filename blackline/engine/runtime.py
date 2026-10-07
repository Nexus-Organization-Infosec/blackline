"""Configurable composition root for plan execution dependencies."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from blackline.engine.events import ExecutionEventCallback, fanout_event_callbacks
from blackline.engine.executor import execute_plan
from blackline.engine.handlers import HandlerRegistry, default_handler_registry
from blackline.engine.models import ExecutionPlan, StepResult
from blackline.engine.scheduler import ExecutionControl, ExecutionProgress, SchedulerOptions
from blackline.utils.exec import CommandResult, CommandTraceCallback


@dataclass(slots=True)
class ExecutionRuntime:
    """Own shared handlers, scheduling policy, command execution, and events."""

    handler_registry: HandlerRegistry = field(default_factory=default_handler_registry)
    scheduler_options: SchedulerOptions = field(default_factory=SchedulerOptions)
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None = None
    event_callback: ExecutionEventCallback | None = None

    def execute(
        self,
        plan: ExecutionPlan,
        *,
        control: ExecutionControl | None = None,
        progress_callback: Callable[[ExecutionProgress], None] | None = None,
        command_callback: CommandTraceCallback | None = None,
        event_callback: ExecutionEventCallback | None = None,
    ) -> tuple[StepResult, ...]:
        """Execute through the configured services with optional run-local observers."""
        events = _combined_events(self.event_callback, event_callback)
        return execute_plan(
            plan,
            command_executor=self.command_executor,
            control=control,
            progress_callback=progress_callback,
            command_callback=command_callback,
            event_callback=events,
            handler_registry=self.handler_registry,
            scheduler_options=self.scheduler_options,
        )


def _combined_events(
    configured: ExecutionEventCallback | None,
    local: ExecutionEventCallback | None,
) -> ExecutionEventCallback | None:
    if configured is None:
        return local
    if local is None or local is configured:
        return configured
    return fanout_event_callbacks(configured, local)
