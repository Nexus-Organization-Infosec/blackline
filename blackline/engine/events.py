"""Structured execution-event helpers and compatibility adapters."""

from __future__ import annotations

from datetime import UTC, datetime
from threading import Lock
from typing import Callable

from blackline.engine.models import ExecutionEvent, PlanStep, StepResult
from blackline.utils.exec import CommandTraceCallback, CommandTraceEvent

ExecutionEventCallback = Callable[[ExecutionEvent], None]


def fanout_event_callbacks(*callbacks: ExecutionEventCallback | None) -> ExecutionEventCallback:
    """Deliver each event to independent consumers without coupling failures."""
    active = tuple(callback for callback in callbacks if callback is not None)

    def callback(event: ExecutionEvent) -> None:
        for consumer in active:
            try:
                consumer(event)
            except Exception:
                continue

    return callback


class EventEmitter:
    """Serialize diagnostic event delivery without affecting execution."""

    def __init__(self, callback: ExecutionEventCallback | None, *, job_id: str = "") -> None:
        self._callback = callback
        self._job_id = job_id
        self._lock = Lock()

    @property
    def enabled(self) -> bool:
        """Return whether this run has an event consumer."""
        return self._callback is not None

    def emit(self, kind: str, *, step_id: str = "", data: dict[str, object] | None = None) -> None:
        if self._callback is None:
            return
        event = ExecutionEvent(
            kind=kind,
            data=data or {},
            job_id=self._job_id,
            step_id=step_id,
            created_at=datetime.now(UTC).isoformat(),
        )
        try:
            with self._lock:
                self._callback(event)
        except Exception:
            return


def step_event_data(step: PlanStep, **extra: object) -> dict[str, object]:
    """Return the stable event representation of a plan step."""
    return {"step": step.to_dict(), **extra}


def result_event_data(result: StepResult, **extra: object) -> dict[str, object]:
    """Return a JSON-compatible result event payload."""
    return {
        "tool": result.tool,
        "action": result.action,
        "ok": result.ok,
        "outcome": result.outcome,
        "error": result.error,
        "payload": dict(result.payload),
        "artifacts": [artifact.to_dict() for artifact in result.artifacts],
        **extra,
    }


def command_event_callback(
    emitter: EventEmitter,
    step: PlanStep,
    legacy_callback: CommandTraceCallback | None,
) -> CommandTraceCallback:
    """Bridge subprocess traces into the unified event stream."""

    def callback(event: CommandTraceEvent) -> None:
        if legacy_callback is not None:
            try:
                legacy_callback(event)
            except Exception:
                pass
        data: dict[str, object] = {
            "args": list(event.args),
            "timeout_seconds": event.timeout,
            "cwd": str(event.cwd) if event.cwd is not None else "",
        }
        if event.result is not None:
            data["result"] = {
                "returncode": event.result.returncode,
                "stdout": event.result.stdout,
                "stderr": event.result.stderr,
                "elapsed_seconds": event.result.elapsed_seconds,
            }
        emitter.emit(f"command.{event.state}", step_id=step.identity, data=data)

    return callback
