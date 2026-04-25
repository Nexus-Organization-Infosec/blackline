"""Execution context."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Structured context for one requested engine run."""

    expression: str
    module: str
    params: dict[str, str] = field(default_factory=dict)
    job_id: str = ""
