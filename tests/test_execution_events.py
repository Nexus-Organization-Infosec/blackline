"""Contracts for the unified structured execution-event stream."""

from __future__ import annotations

import json
import sys
import unittest

from blackline.core.artifacts import Artifact
from blackline.engine.context import ExecutionContext
from blackline.engine.executor import execute_plan
from blackline.engine.handlers import HandlerRegistry
from blackline.engine.models import ExecutionEvent, ExecutionPlan, PlanStep, RetryPolicy, StepId, StepResult
from blackline.utils.exec import run_command


class ExecutionEventTests(unittest.TestCase):
    def test_events_cover_plan_step_retry_and_artifact_lifecycle(self):
        attempts = 0
        events: list[ExecutionEvent] = []

        def handler(step, _context):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return StepResult(step.tool, step.action, False, {}, "temporary")
            return StepResult(
                step.tool,
                step.action,
                True,
                {},
                artifacts=(Artifact("fact", "target", source_step=step.identity, source_provider="custom"),),
            )

        registry = HandlerRegistry()
        registry.register("custom", handler)
        plan = ExecutionPlan(
            ExecutionContext("", "", job_id="JOB-1"),
            (
                PlanStep(
                    "custom",
                    "run",
                    id=StepId("custom.run.1"),
                    retry_policy=RetryPolicy(max_attempts=2, retryable_outcomes=("failed",)),
                ),
            ),
        )

        execute_plan(plan, handler_registry=registry, event_callback=events.append)

        kinds = [event.kind for event in events]
        self.assertEqual(kinds[0], "plan.started")
        self.assertIn("step.queued", kinds)
        self.assertEqual(kinds.count("step.started"), 2)
        self.assertIn("step.retrying", kinds)
        self.assertIn("step.completed", kinds)
        self.assertIn("artifact.created", kinds)
        self.assertEqual(kinds[-1], "plan.completed")
        self.assertTrue(all(event.job_id == "JOB-1" for event in events))
        self.assertTrue(all(event.created_at for event in events))
        json.dumps([event.to_dict() for event in events])

    def test_event_callback_failure_does_not_change_execution(self):
        registry = HandlerRegistry()
        registry.register("custom", lambda step, _context: StepResult(step.tool, step.action, True, {}))
        plan = ExecutionPlan(
            ExecutionContext("", ""),
            (PlanStep("custom", "run", id=StepId("custom.run.1")),),
        )

        results = execute_plan(
            plan,
            handler_registry=registry,
            event_callback=lambda _event: (_ for _ in ()).throw(RuntimeError("renderer failed")),
        )

        self.assertTrue(results[0].ok)

    def test_subprocess_traces_are_part_of_the_same_event_stream(self):
        events: list[ExecutionEvent] = []

        def handler(step, _context):
            command = run_command((sys.executable, "-c", "print('event-output')"))
            return StepResult(step.tool, step.action, command.ok, {"stdout": command.stdout})

        registry = HandlerRegistry()
        registry.register("custom", handler)
        plan = ExecutionPlan(
            ExecutionContext("", ""),
            (PlanStep("custom", "run", id=StepId("custom.run.1")),),
        )

        execute_plan(plan, handler_registry=registry, event_callback=events.append)

        started = next(event for event in events if event.kind == "command.started")
        completed = next(event for event in events if event.kind == "command.completed")
        self.assertEqual(started.step_id, "custom.run.1")
        self.assertEqual(started.data["args"][:2], [sys.executable, "-c"])
        self.assertIn("event-output", completed.data["result"]["stdout"])


if __name__ == "__main__":
    unittest.main()
