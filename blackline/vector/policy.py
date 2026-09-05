"""Explicit permission filtering separate from Vector planning."""

from __future__ import annotations

from dataclasses import dataclass, field

from blackline.vector.capability import Capability
from blackline.vector.goal import Goal


@dataclass(frozen=True, slots=True)
class PolicyResult:
    """The explainable outcome of evaluating one candidate."""

    allowed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class Policy:
    """Conservative v0 policy with optional action allow-list and risk ceiling."""

    allowed_actions: frozenset[str] = field(default_factory=frozenset)
    maximum_risk: int = 0

    def evaluate(self, capability: Capability, goal: Goal) -> PolicyResult:
        """Decide whether a useful capability may be scheduled."""
        if self.allowed_actions and capability.identity not in self.allowed_actions:
            return PolicyResult(False, "capability is not in the allowed action set")
        if capability.risk > self.maximum_risk:
            return PolicyResult(False, f"capability risk {capability.risk} exceeds policy limit {self.maximum_risk}")
        if capability.goal_actions and goal.action not in capability.goal_actions:
            return PolicyResult(False, f"capability does not apply to goal action {goal.action}")
        return PolicyResult(True, "capability is permitted")
