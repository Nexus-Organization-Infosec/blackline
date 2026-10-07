"""Contracts for the configurable public execution runtime."""

from __future__ import annotations

import unittest

from blackline.engine import ExecutionRuntime, SchedulerOptions
from blackline.engine.context import ExecutionContext
from blackline.engine.handlers import HandlerRegistry
from blackline.engine.models import ExecutionPlan, PlanStep, StepId, StepResult
from blackline.engine.runner import run_expression


class ExecutionRuntimeTests(unittest.TestCase):
    def test_runtime_composes_handlers_policy_commands_and_event_consumers(self):
        configured_events: list[str] = []
        local_events: list[str] = []
        commands: list[tuple[str, ...]] = []
        registry = HandlerRegistry()

        def handler(step, context):
            assert context.command_executor is not None
            command = ("custom", step.action)
            execution = context.command_executor(command)
            return StepResult(step.tool, step.action, execution.ok, {"stdout": execution.stdout})

        from blackline.utils.exec import CommandResult

        registry.register("custom", handler)
        runtime = ExecutionRuntime(
            handler_registry=registry,
            scheduler_options=SchedulerOptions(max_concurrency=1),
            command_executor=lambda args: commands.append(args) or CommandResult(args, 0, "ok", "", 0.0),
            event_callback=lambda event: configured_events.append(event.kind),
        )
        plan = ExecutionPlan(
            ExecutionContext("", "", job_id="JOB1"),
            (PlanStep("custom", "collect", id=StepId("custom.collect.1")),),
        )

        results = runtime.execute(plan, event_callback=lambda event: local_events.append(event.kind))

        self.assertEqual(commands, [("custom", "collect")])
        self.assertEqual(results[0].payload["stdout"], "ok")
        self.assertEqual(configured_events, local_events)
        self.assertEqual(configured_events[0], "plan.started")
        self.assertEqual(configured_events[-1], "plan.completed")

    def test_runner_uses_an_injected_runtime_without_changing_legacy_callers(self):
        events: list[str] = []
        runtime = ExecutionRuntime(event_callback=lambda event: events.append(event.kind))

        result = run_expression("unknown", runtime=runtime)

        self.assertEqual(result.results, ())
        self.assertEqual(events, ["plan.started", "plan.completed"])


if __name__ == "__main__":
    unittest.main()
