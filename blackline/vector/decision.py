"""Structured decision traces for Vector explainability and tests."""

from __future__ import annotations

from dataclasses import dataclass, field

from blackline.vector.candidate import Candidate
from blackline.vector.state import StateDelta


@dataclass(frozen=True, slots=True)
class Rejection:
    """One candidate Vector considered but could not select."""

    candidate: Candidate
    reason: str


@dataclass(frozen=True, slots=True)
class Decision:
    """One deterministic Vector decision cycle."""

    cycle: int
    delta: StateDelta
    candidates: tuple[Candidate, ...]
    selected: tuple[Candidate, ...]
    rejected: tuple[Rejection, ...] = field(default_factory=tuple)

    def explain(self, identity: str) -> tuple[str, ...]:
        """Return the recorded explanation for a selected or rejected action."""
        for candidate in self.selected:
            if candidate.identity == identity:
                return candidate.reason
        for rejection in self.rejected:
            if rejection.candidate.identity == identity:
                return (*rejection.candidate.reason, rejection.reason)
        return ()
