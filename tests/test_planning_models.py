"""Contracts for the versioned planning model."""

from __future__ import annotations

import unittest

from blackline.engine.context import ExecutionContext
from blackline.engine.models import (
    Artifact,
    ExecutionEvent,
    ExecutionPlan,
    PlanStep,
    PlanValidationError,
    RetryPolicy,
    StepDependency,
    StepId,
)
from blackline.engine.planner import build_plan


class PlanningModelTests(unittest.TestCase):
    def test_legacy_plan_step_constructor_remains_supported(self):
        step = PlanStep("nmap", "port_scan", {"target": "192.0.2.10"}, 2)

        self.assertEqual(step.tool, "nmap")
        self.assertEqual(step.action, "port_scan")
        self.assertEqual(step.params, {"target": "192.0.2.10"})
        self.assertEqual(step.execution_group, 2)
        self.assertEqual(step.identity, "nmap.port_scan")

    def test_planner_assigns_deterministic_ids_capabilities_and_reasons(self):
        context = ExecutionContext(
            expression="recon[target=example.com]",
            module="recon",
            params={"target": "example.com"},
        )

        first = build_plan(context)
        second = build_plan(context)

        self.assertEqual(
            [step.identity for step in first.steps],
            [step.identity for step in second.steps],
        )
        self.assertEqual(len({step.identity for step in first.steps}), len(first.steps))
        self.assertEqual(first.steps[0].capability, "dns.resolve")
        self.assertEqual(first.steps[-1].capability, "network.service_identify")
        self.assertEqual(first.steps[0].timeout_seconds, 15.0)
        self.assertEqual(first.steps[0].produces, ("host.ip", "dns.record"))
        self.assertIsNone(first.steps[-1].timeout_seconds)
        self.assertTrue(all(step.reason for step in first.steps))

    def test_plan_serialization_is_provider_and_capability_aware(self):
        context = ExecutionContext("recon[target=example.com]", "recon", {"target": "example.com"})
        plan = ExecutionPlan(
            context=context,
            steps=(
                PlanStep(
                    tool="dns",
                    action="dns",
                    params={"host": "example.com"},
                    id=StepId("dns.primary"),
                    capability="dns.resolve",
                    produces=("dns.record", "host.ip"),
                    reason="resolve the target",
                ),
            ),
        )

        serialized = plan.to_dict()

        self.assertEqual(serialized["schema_version"], 1)
        self.assertEqual(serialized["steps"][0]["id"], "dns.primary")
        self.assertEqual(serialized["steps"][0]["provider"], "dns")
        self.assertEqual(serialized["steps"][0]["capability"], "dns.resolve")
        self.assertEqual(serialized["steps"][0]["produces"], ["dns.record", "host.ip"])

    def test_plan_validation_rejects_unknown_dependencies(self):
        plan = ExecutionPlan(
            context=ExecutionContext("", ""),
            steps=(
                PlanStep(
                    "http",
                    "probe",
                    id=StepId("http.probe"),
                    depends_on=(StepDependency(StepId("dns.missing")),),
                ),
            ),
        )

        with self.assertRaisesRegex(PlanValidationError, "unknown steps"):
            plan.validate()

    def test_retry_policy_is_bounded(self):
        self.assertEqual(RetryPolicy().max_attempts, 1)
        with self.assertRaisesRegex(ValueError, "at least 1"):
            RetryPolicy(max_attempts=0)
        with self.assertRaisesRegex(ValueError, "cannot be negative"):
            RetryPolicy(backoff_seconds=-1)

    def test_artifacts_and_events_have_versioned_serialization(self):
        artifact = Artifact(
            kind="host.port",
            subject="192.0.2.10",
            data={"port": 443, "state": "open"},
            source_step="ports.discover",
            source_provider="naabu",
        )
        event = ExecutionEvent(
            kind="artifact.created",
            step_id="ports.discover",
            data={"artifact": artifact.to_dict()},
        )

        self.assertEqual(artifact.to_dict()["schema_version"], 1)
        self.assertEqual(event.to_dict()["schema_version"], 1)
        self.assertEqual(event.to_dict()["data"]["artifact"]["kind"], "host.port")


if __name__ == "__main__":
    unittest.main()
