"""Incremental matching of Vector capabilities and compiled CLT rules."""

from __future__ import annotations

from collections import defaultdict

from blackline.clt.ir import ActionIntent, ConditionIntent, IRFlow, IRRule
from blackline.vector.capability import Capability
from blackline.vector.state import StateDelta, VectorState


class Resolver:
    """Resolve applicable capabilities through requirements and indexed rules."""

    def __init__(self) -> None:
        self._capabilities: dict[str, Capability] = {}
        self._capabilities_by_requirement: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        self._unconditional: set[str] = set()
        self._rules: list[IRRule] = []
        self._rules_by_condition: dict[tuple[str, str, str], list[IRRule]] = defaultdict(list)

    def register_capability(self, capability: Capability) -> None:
        """Register a capability and index its prerequisites."""
        if capability.identity in self._capabilities:
            raise ValueError(f"Vector capability already registered: {capability.identity}")
        self._capabilities[capability.identity] = capability
        if not capability.requirements:
            self._unconditional.add(capability.identity)
        for requirement in capability.requirements:
            self._capabilities_by_requirement[_condition_key(requirement)].add(capability.identity)

    def register_rule(self, rule: IRRule) -> None:
        """Register one already-compiled CLT rule; Vector never parses source."""
        self._rules.append(rule)
        self._rules_by_condition[_condition_key(rule.condition)].append(rule)

    def applicable_capabilities(self, state: VectorState, delta: StateDelta | None = None) -> tuple[Capability, ...]:
        """Return capabilities whose requirements currently hold, incrementally."""
        identities = self._candidate_capability_ids(delta)
        return tuple(
            self._capabilities[identity]
            for identity in sorted(identities)
            if all(state.holds(requirement) for requirement in self._capabilities[identity].requirements)
        )

    def matching_rule_actions(self, state: VectorState, delta: StateDelta | None = None) -> tuple[tuple[IRRule, ActionIntent], ...]:
        """Return action intents produced by rules whose conditions now hold."""
        rules = self._candidate_rules(delta)
        matches: list[tuple[IRRule, ActionIntent]] = []
        for rule in rules:
            if not state.holds(rule.condition):
                continue
            for statement in rule.body:
                if isinstance(statement, IRFlow):
                    matches.append((rule, statement.intent))
        return tuple(matches)

    def capability_for_intent(self, intent: ActionIntent) -> Capability | None:
        """Resolve an action requested by a rule to its registered capability."""
        exact = f"{intent.verb}:{intent.subject}".rstrip(":")
        return self._capabilities.get(exact) or self._capabilities.get(intent.verb)

    def _candidate_capability_ids(self, delta: StateDelta | None) -> set[str]:
        if delta is None:
            return set(self._capabilities)
        identities = set(self._unconditional)
        for key in _delta_condition_keys(delta):
            identities.update(self._capabilities_by_requirement.get(key, set()))
        return identities

    def _candidate_rules(self, delta: StateDelta | None) -> tuple[IRRule, ...]:
        if delta is None:
            return tuple(self._rules)
        matches: list[IRRule] = []
        seen: set[int] = set()
        for key in _delta_condition_keys(delta):
            for rule in self._rules_by_condition.get(key, ()):
                if id(rule) not in seen:
                    matches.append(rule)
                    seen.add(id(rule))
        return tuple(matches)


def _condition_key(condition: ConditionIntent) -> tuple[str, str, str]:
    return condition.entity, condition.value, condition.state


def _delta_condition_keys(delta: StateDelta) -> set[tuple[str, str, str]]:
    keys = set(delta.facts)
    for service in delta.services:
        keys.add(("service", service.protocol, service.state))
        keys.add(("port", str(service.port), service.state))
    return keys
