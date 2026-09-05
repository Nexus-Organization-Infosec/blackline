"""The small deterministic Vector decision cycle."""

from __future__ import annotations

from collections.abc import Iterable

from blackline.clt.ir import IRRule
from blackline.vector.capability import Capability
from blackline.vector.decision import Decision, Rejection
from blackline.vector.goal import Goal
from blackline.vector.observation import Observation
from blackline.vector.planner import Planner
from blackline.vector.policy import Policy
from blackline.vector.resolver import Resolver
from blackline.vector.scorer import rank, score
from blackline.vector.state import StateDelta, VectorState


class Vector:
    """Adaptive planner that turns state deltas into explainable next actions."""

    def __init__(self, goal: Goal, *, policy: Policy | None = None) -> None:
        self.goal = goal
        self.policy = policy or Policy()
        self.state = VectorState()
        self.resolver = Resolver()
        self.planner = Planner()
        self._cycle = 0
        self._completed: set[str] = set()
        self._decisions: list[Decision] = []

    @property
    def decisions(self) -> tuple[Decision, ...]:
        """Return the immutable decision trace produced so far."""
        return tuple(self._decisions)

    def register_capability(self, capability: Capability) -> None:
        """Add an action Vector may consider in future cycles."""
        self.resolver.register_capability(capability)

    def register_rule(self, rule: IRRule) -> None:
        """Add a normalized CLT rule without allowing Vector to parse CLT."""
        self.resolver.register_rule(rule)

    def observe(self, observations: Iterable[Observation]) -> Decision:
        """Ingest a state delta and select permitted next work deterministically."""
        delta = self.state.ingest(observations)
        return self._decide(delta)

    def decide(self) -> Decision:
        """Reconsider currently applicable work without needing new observations."""
        return self._decide(StateDelta(self.state.revision))

    def mark_completed(self, candidate: Candidate | str) -> None:
        """Record completed work so equivalent future candidates are deduplicated."""
        self._completed.add(candidate if isinstance(candidate, str) else candidate.identity)

    def _decide(self, delta: StateDelta) -> Decision:
        self._cycle += 1
        raw_candidates = self.planner.candidates(
            self.goal,
            self.state,
            self.resolver,
            delta=delta if delta.changed else None,
            completed=frozenset(self._completed),
        )
        candidates = []
        rejected: list[Rejection] = []
        for candidate in raw_candidates:
            capability = self.resolver.capability_for_intent(candidate.intent)
            if capability is None:
                continue
            policy = self.policy.evaluate(capability, self.goal)
            if not policy.allowed:
                rejected.append(Rejection(candidate, policy.reason))
                continue
            candidates.append(score(candidate, capability, self.goal))
        ranked = rank(candidates)
        selected = ranked[:1]
        decision = Decision(self._cycle, delta, ranked, selected, tuple(rejected))
        self._decisions.append(decision)
        return decision
