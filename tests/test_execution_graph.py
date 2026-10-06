"""Contracts for dependency-graph validation and scheduling."""

from __future__ import annotations

import unittest

from blackline.engine.context import ExecutionContext
from blackline.engine.executor import execute_step
from blackline.engine.graph import dependency_waves
from blackline.engine.handlers import HandlerRegistry
from blackline.engine.models import ExecutionPlan, PlanStep, PlanValidationError, StepDependency, StepId, StepResult
from blackline.engine.planner import build_plan


class ExecutionGraphTests(unittest.TestCase):
    def test_planner_materializes_existing_execution_waves_as_dependencies(self):
        plan = build_plan(ExecutionContext("recon[target=example.com]", "recon", {"target": "example.com"}))
        dns = next(step for step in plan.steps if step.tool == "dns")
        nmap = next(step for step in plan.steps if step.tool == "nmap")
        httpx = next(step for step in plan.steps if step.tool == "httpx")

        self.assertEqual(dns.depends_on, ())
        self.assertIn(dns.identity, {str(item.step_id) for item in nmap.depends_on})
        self.assertIn(nmap.identity, {str(item.step_id) for item in httpx.depends_on})
        self.assertTrue(all(item.optional for item in nmap.depends_on))

    def test_graph_builds_stable_topological_waves(self):
        steps = (
            PlanStep("dns", "resolve", id=StepId("dns")),
            PlanStep("naabu", "scan", id=StepId("ports")),
            PlanStep("nmap", "enrich", id=StepId("services"), depends_on=(StepDependency(StepId("ports")),)),
            PlanStep("httpx", "probe", id=StepId("web"), depends_on=(StepDependency(StepId("services")),)),
        )

        self.assertEqual(dependency_waves(steps), ((0, 1), (2,), (3,)))

    def test_plan_validation_rejects_cycles(self):
        plan = ExecutionPlan(
            ExecutionContext("", ""),
            (
                PlanStep("a", "run", id=StepId("a"), depends_on=(StepDependency(StepId("b")),)),
                PlanStep("b", "run", id=StepId("b"), depends_on=(StepDependency(StepId("a")),)),
            ),
        )

        with self.assertRaisesRegex(PlanValidationError, "dependency cycle"):
            plan.validate()

    def test_required_artifacts_skip_a_handler_when_evidence_is_missing(self):
        calls: list[str] = []
        registry = HandlerRegistry()
        registry.register("custom", lambda step, context: calls.append(step.identity) or StepResult(step.tool, step.action, True, {}))
        step = PlanStep(
            "custom",
            "run",
            id=StepId("custom.run"),
            depends_on=(StepDependency(StepId("dns"), required_artifacts=("host.ip",)),),
        )

        result = execute_step(step, handler_registry=registry)

        self.assertEqual(calls, [])
        self.assertTrue(result.ok)
        self.assertEqual(result.outcome, "skipped")
        self.assertIn("host.ip", result.payload["skip_reason"])


if __name__ == "__main__":
    unittest.main()
