"""Persistent shell history storage."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

FILTERED_COMMANDS = {"clear"}


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    """One persisted shell history entry."""

    command: str
    created: str


def append_history(command: str, *, history_path: Path | None = None, created_at: datetime | None = None) -> None:
    """Append one command to persistent history."""
    history_path = history_path or default_history_path()
    history_path.parent.mkdir(parents=True, exist_ok=True)
    entry = HistoryEntry(command=command, created=(created_at or datetime.now()).isoformat(timespec="seconds"))
    with history_path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(asdict(entry)) + "\n")


def load_history(*, history_path: Path | None = None, include_filtered: bool = False) -> list[HistoryEntry]:
    """Load persisted history entries."""
    history_path = history_path or default_history_path()
    if not history_path.exists():
        return []

    entries: list[HistoryEntry] = []
    for line in history_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        entry = HistoryEntry(command=str(data.get("command", "")), created=str(data.get("created", "")))
        if include_filtered or entry.command.split(maxsplit=1)[0].lower() not in FILTERED_COMMANDS:
            entries.append(entry)
    return entries


def clear_history(*, history_path: Path | None = None) -> None:
    """Remove persisted history entries."""
    history_path = history_path or default_history_path()
    if history_path.exists():
        history_path.unlink()


def default_history_path() -> Path:
    """Return the default persistent history log path."""
    return Path(__file__).resolve().parent / "history" / "commands.jsonl"
