"""Contracts for provider handler registration and generic dispatch."""

from __future__ import annotations

import unittest

from blackline.engine.executor import execute_step
from blackline.engine.handlers import HandlerRegistry, default_handler_registry
from blackline.engine.models import PlanStep, StepResult


class ExecutionHandlerTests(unittest.TestCase):
    def test_default_registry_has_one_handler_for_every_current_provider(self):
        registry = default_handler_registry()

        self.assertEqual(
            registry.names,
            (
                "dns",
                "subfinder",
                "ipintel",
                "rdap",
                "http",
                "httpx",
                "fingerprint",
                "whatweb",
                "katana",
                "tls",
                "sslyze",
                "rpcinfo",
                "smbclient",
                "naabu",
                "nmap",
            ),
        )

    def test_registry_rejects_duplicate_names(self):
        registry = HandlerRegistry()
        registry.register("custom", lambda step, context: StepResult(step.tool, step.action, True, {}))

        with self.assertRaisesRegex(ValueError, "duplicate execution handler"):
            registry.register("custom", lambda step, context: StepResult(step.tool, step.action, True, {}))

    def test_executor_dispatches_unknown_provider_through_an_explicit_registry(self):
        registry = HandlerRegistry()
        registry.register(
            "custom",
            lambda step, context: StepResult(
                step.tool,
                step.action,
                True,
                {"provider": "custom", "value": step.params.get("value", "")},
            ),
        )

        result = execute_step(
            PlanStep("custom", "collect", {"value": "evidence"}),
            handler_registry=registry,
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.payload["value"], "evidence")

    def test_executor_returns_a_structured_failure_for_missing_handler(self):
        result = execute_step(PlanStep("missing", "collect"), handler_registry=HandlerRegistry())

        self.assertFalse(result.ok)
        self.assertEqual(result.outcome, "failed")
        self.assertEqual(result.error, "unsupported tool: missing")


if __name__ == "__main__":
    unittest.main()
