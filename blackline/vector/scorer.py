"""Small, explainable initial candidate ranking for Vector."""

from __future__ import annotations

from dataclasses import replace

from blackline.vector.candidate import Candidate
from blackline.vector.capability import Capability
from blackline.vector.goal import Goal


def score(candidate: Candidate, capability: Capability, goal: Goal) -> Candidate:
    """Score one candidate with transparent strategy-sensitive cost handling."""
    cost_weight = {"fast": 2, "balanced": 1, "deep": 0}[goal.strategy]
    score_value = capability.priority - capability.risk - (capability.cost * cost_weight)
    return replace(candidate, score=score_value)


def rank(candidates: list[Candidate]) -> tuple[Candidate, ...]:
    """Rank candidates deterministically; ties never depend on insertion order."""
    return tuple(sorted(candidates, key=lambda candidate: (-candidate.score, candidate.identity)))
