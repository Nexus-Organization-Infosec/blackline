"""End-to-end proof that new capabilities use public seams only."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from blackline.core.artifacts import Artifact
from blackline.core.jobs import Job
from blackline.engine import ExecutionPlan, ExecutionRuntime, PlanStep, StepResult
from blackline.engine.context import ExecutionContext
from blackline.engine.handlers import HandlerRegistry
from blackline.engine.models import StepId
from blackline.storage.event_journal import JsonlEventJournal
from blackline.storage.job_store import JsonJobRepository


class ExtensionPathTests(unittest.TestCase):
    def test_custom_capability_executes_persists_and_replays_without_core_edits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs = JsonJobRepository(root / "jobs")
            journal = JsonlEventJournal(root / "events" / "EXT1.jsonl")
            registry = HandlerRegistry()

            def collect(step, _context):
                artifact = Artifact(
                    "custom.fact",
                    str(step.params["target"]),
                    {"value": "observed"},
                    source_step=step.identity,
                    source_provider="example",
                )
                return StepResult(step.tool, step.action, True, {"value": "observed"}, artifacts=(artifact,))

            registry.register("example", collect)
            runtime = ExecutionRuntime(handler_registry=registry, event_callback=journal.append)
            plan = ExecutionPlan(
                ExecutionContext("example[target=asset]", "example", {"target": "asset"}, job_id="EXT1"),
                (PlanStep("example", "collect", {"target": "asset"}, id=StepId("example.collect.1")),),
            )
            jobs.save(Job("EXT1", "example", {"target": "asset"}, "2026-10-06 12:00", target="asset"))

            result = runtime.execute(plan)[0]
            jobs.append_result("EXT1", result.to_dict())

            saved = jobs.load("EXT1")
            assert saved is not None
            self.assertEqual(saved.results[0]["payload"]["value"], "observed")
            self.assertEqual(saved.steps[0]["artifacts"][0]["kind"], "custom.fact")
            self.assertEqual(journal.load()[0].kind, "plan.started")
            self.assertEqual(journal.load()[-1].kind, "plan.completed")


if __name__ == "__main__":
    unittest.main()
