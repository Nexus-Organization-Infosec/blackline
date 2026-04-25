"""Session state."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class EngineSession:
    """Long-lived engine session state."""

    active_job: str = ""
    runs: list[str] = field(default_factory=list)
