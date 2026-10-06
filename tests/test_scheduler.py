"""Contracts for bounded scheduling, retries, dependencies, and cancellation."""

from __future__ import annotations

from threading import Lock
import time
import unittest

from blackline.engine.context import ExecutionContext
from blackline.engine.executor import ExecutionControl, SchedulerOptions, execute_plan
from blackline.engine.handlers import HandlerRegistry
from blackline.engine.models import ExecutionPlan, PlanStep, RetryPolicy, StepDependency, StepId, StepResult


class SchedulerTests(unittest.TestCase):
    def test_scheduler_bounds_concurrency_and_preserves_plan_order(self):
        lock = Lock()
        active = 0
        high_water = 0

        def handler(step, _context):
            nonlocal active, high_water
            with lock:
                active += 1
                high_water = max(high_water, active)
            time.sleep(0.02 if step.identity != "step.0" else 0.04)
            with lock:
                active -= 1
            return StepResult(step.tool, step.action, True, {"id": step.identity})

        registry = HandlerRegistry()
        registry.register("custom", handler)
        plan = ExecutionPlan(
            ExecutionContext("", ""),
            tuple(PlanStep("custom", "run", id=StepId(f"step.{index}")) for index in range(6)),
        )

        results = execute_plan(plan, handler_registry=registry, scheduler_options=SchedulerOptions(max_concurrency=2))

        self.assertEqual(high_water, 2)
        self.assertEqual([result.payload["id"] for result in results], [f"step.{index}" for index in range(6)])

    def test_scheduler_retries_only_configured_outcomes(self):
        attempts = 0

        def handler(step, _context):
            nonlocal attempts
            attempts += 1
            return StepResult(step.tool, step.action, attempts == 3, {}, "temporary" if attempts < 3 else "")

        registry = HandlerRegistry()
        registry.register("custom", handler)
        plan = ExecutionPlan(
            ExecutionContext("", ""),
            (
                PlanStep(
                    "custom",
                    "run",
                    id=StepId("retry"),
                    retry_policy=RetryPolicy(max_attempts=3, retryable_outcomes=("failed",)),
                ),
            ),
        )

        results = execute_plan(plan, handler_registry=registry)

        self.assertEqual(attempts, 3)
        self.assertTrue(results[0].ok)

    def test_required_dependency_failure_skips_downstream_handler(self):
        calls: list[str] = []

        def handler(step, _context):
            calls.append(step.identity)
            return StepResult(step.tool, step.action, step.identity != "upstream", {}, "failed" if step.identity == "upstream" else "")

        registry = HandlerRegistry()
        registry.register("custom", handler)
        plan = ExecutionPlan(
            ExecutionContext("", ""),
            (
                PlanStep("custom", "run", id=StepId("upstream")),
                PlanStep(
                    "custom",
                    "run",
                    id=StepId("downstream"),
                    depends_on=(StepDependency(StepId("upstream")),),
                ),
            ),
        )

        results = execute_plan(plan, handler_registry=registry)

        self.assertEqual(calls, ["upstream"])
        self.assertEqual(results[1].outcome, "skipped")
        self.assertIn("upstream", results[1].payload["skip_reason"])

    def test_cancellation_finishes_running_work_but_starts_no_later_wave(self):
        control = ExecutionControl()
        calls: list[str] = []

        def handler(step, _context):
            calls.append(step.identity)
            control.cancel("test stop")
            return StepResult(step.tool, step.action, True, {})

        registry = HandlerRegistry()
        registry.register("custom", handler)
        plan = ExecutionPlan(
            ExecutionContext("", ""),
            (
                PlanStep("custom", "run", id=StepId("first")),
                PlanStep("custom", "run", id=StepId("later"), depends_on=(StepDependency(StepId("first")),)),
            ),
        )

        results = execute_plan(plan, handler_registry=registry, control=control)

        self.assertEqual(calls, ["first"])
        self.assertEqual(len(results), 1)
        self.assertEqual(control.cancellation_reason, "test stop")


if __name__ == "__main__":
    unittest.main()
