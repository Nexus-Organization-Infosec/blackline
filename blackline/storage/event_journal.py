"""Optional JSONL persistence for structured execution events."""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Protocol

from blackline.engine.models import ExecutionEvent


class EventJournal(Protocol):
    """Append-only persistence contract for execution events."""

    def append(self, event: ExecutionEvent) -> None: ...

    def load(self) -> tuple[ExecutionEvent, ...]: ...


class JsonlEventJournal:
    """Persist and replay versioned events without requiring a database."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = Lock()

    def append(self, event: ExecutionEvent) -> None:
        serialized = json.dumps(event.to_dict(), separators=(",", ":"))
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as file:
                file.write(serialized + "\n")

    def load(self) -> tuple[ExecutionEvent, ...]:
        if not self.path.exists():
            return ()
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return ()
        events: list[ExecutionEvent] = []
        for line in lines:
            event = _decode_event(line)
            if event is not None:
                events.append(event)
        return tuple(events)


def _decode_event(line: str) -> ExecutionEvent | None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or not str(data.get("kind", "")).strip():
        return None
    payload = data.get("data", {})
    if not isinstance(payload, dict):
        payload = {}
    try:
        schema_version = int(data.get("schema_version", 1))
    except (TypeError, ValueError):
        schema_version = 1
    return ExecutionEvent(
        kind=str(data["kind"]),
        data=payload,
        job_id=str(data.get("job_id", "")),
        step_id=str(data.get("step_id", "")),
        created_at=str(data.get("created_at", "")),
        schema_version=max(1, schema_version),
    )
