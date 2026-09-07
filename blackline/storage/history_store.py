"""Persistent shell history storage."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

FILTERED_COMMANDS = {"clear"}


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    """One persisted shell history entry."""

    command: str
    created: str


def append_history(command: str, *, history_path: Path | None = None, created_at: datetime | None = None) -> bool:
    """Append one command to persistent history without breaking the shell on I/O errors."""
    history_path = history_path or default_history_path()
    try:
        history_path.parent.mkdir(parents=True, exist_ok=True)
        entry = HistoryEntry(command=command, created=(created_at or datetime.now()).isoformat(timespec="seconds"))
        with history_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(asdict(entry)) + "\n")
    except OSError:
        return False
    return True


def load_history(*, history_path: Path | None = None, include_filtered: bool = False) -> list[HistoryEntry]:
    """Load persisted history entries."""
    history_path = history_path or default_history_path()
    if not history_path.exists():
        return []

    entries: list[HistoryEntry] = []
    try:
        lines = history_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in lines:
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        entry = HistoryEntry(command=str(data.get("command", "")).strip(), created=str(data.get("created", "")))
        if not entry.command:
            continue
        if include_filtered or entry.command.split(maxsplit=1)[0].lower() not in FILTERED_COMMANDS:
            entries.append(entry)
    return entries


def clear_history(*, history_path: Path | None = None) -> None:
    """Remove persisted history entries."""
    history_path = history_path or default_history_path()
    try:
        if history_path.exists():
            history_path.unlink()
    except OSError:
        return


def default_history_path() -> Path:
    """Return a user-local runtime history log, outside the repository."""
    configured_root = os.environ.get("BLACKLINE_DATA_DIR", "").strip()
    root = Path(configured_root).expanduser() if configured_root else Path.home() / ".blackline"
    return root / "history" / "commands.jsonl"
