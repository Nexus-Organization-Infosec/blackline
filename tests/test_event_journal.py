"""Contracts for optional execution-event persistence and fan-out."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from blackline.engine.events import fanout_event_callbacks
from blackline.engine.context import ExecutionContext
from blackline.engine.executor import execute_plan
from blackline.engine.handlers import HandlerRegistry
from blackline.engine.models import ExecutionEvent, ExecutionPlan, PlanStep, StepId, StepResult
from blackline.storage.event_journal import JsonlEventJournal


class EventJournalTests(unittest.TestCase):
    def test_jsonl_journal_round_trips_events_and_ignores_bad_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events" / "JOB1.jsonl"
            journal = JsonlEventJournal(path)
            event = ExecutionEvent("step.completed", {"outcome": "done"}, "JOB1", "step.1", "now")
            journal.append(event)
            with path.open("a", encoding="utf-8") as file:
                file.write("not-json\n")

            self.assertEqual(journal.load(), (event,))

    def test_fanout_keeps_consumers_independent(self):
        received: list[str] = []
        callback = fanout_event_callbacks(
            lambda _event: (_ for _ in ()).throw(RuntimeError("failed consumer")),
            lambda event: received.append(event.kind),
        )

        callback(ExecutionEvent("plan.started"))

        self.assertEqual(received, ["plan.started"])

    def test_journal_connects_directly_to_the_execution_event_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = JsonlEventJournal(Path(tmp) / "JOB1.jsonl")
            registry = HandlerRegistry()
            registry.register("custom", lambda step, _context: StepResult(step.tool, step.action, True, {}))
            plan = ExecutionPlan(
                ExecutionContext("", "", job_id="JOB1"),
                (PlanStep("custom", "run", id=StepId("custom.run.1")),),
            )

            execute_plan(plan, handler_registry=registry, event_callback=journal.append)

            events = journal.load()
            self.assertEqual(events[0].kind, "plan.started")
            self.assertEqual(events[-1].kind, "plan.completed")
            self.assertTrue(all(event.job_id == "JOB1" for event in events))


if __name__ == "__main__":
    unittest.main()
