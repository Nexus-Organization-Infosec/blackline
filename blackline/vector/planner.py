"""Candidate generation and deduplication for Vector's first decision cycle."""

from __future__ import annotations

from blackline.vector.candidate import Candidate
from blackline.vector.goal import Goal
from blackline.vector.resolver import Resolver
from blackline.vector.state import ServiceFact, StateDelta, VectorState


class Planner:
    """Generate candidates without executing tools or making policy decisions."""

    def candidates(
        self,
        goal: Goal,
        state: VectorState,
        resolver: Resolver,
        *,
        delta: StateDelta | None = None,
        completed: frozenset[str] = frozenset(),
    ) -> tuple[Candidate, ...]:
        """Create only new, currently applicable candidates from state changes."""
        candidates: dict[str, Candidate] = {}
        for capability in resolver.applicable_capabilities(state, delta):
            # An unconstrained capability is inert until a compiled rule (or a
            # future explicit goal applicability declaration) makes it useful.
            if not capability.requirements:
                continue
            services = _matching_services(state, capability.requirements)
            if not services:
                has_service_requirement = any(requirement.entity in {"service", "port"} for requirement in capability.requirements)
                if not has_service_requirement:
                    reasons = tuple(f"requirement satisfied: {requirement.entity} {requirement.value} {requirement.state}" for requirement in capability.requirements)
                    sources = tuple(source for requirement in capability.requirements for source in state.condition_sources(requirement))
                    _add_candidate(candidates, _candidate_for(capability, goal.target, reasons, sources), completed)
                continue
            else:
                for service in services:
                    reasons = tuple(f"requirement satisfied: {requirement.entity} {requirement.value} {requirement.state}" for requirement in capability.requirements)
                    _add_candidate(candidates, _candidate_for(capability, service.target, reasons, service.sources), completed)

        for rule, intent in resolver.matching_rule_actions(state, delta):
            capability = resolver.capability_for_intent(intent)
            if capability is None:
                continue
            services = state.matches(rule.condition)
            targets = services or (None,)
            for service in targets:
                target = service.target if service is not None else goal.target
                sources = service.sources if service is not None else state.condition_sources(rule.condition)
                reason = (f"CLT rule matched: {rule.condition.entity} {rule.condition.value} {rule.condition.state}",)
                _add_candidate(candidates, _candidate_for(capability, target, reason, sources), completed)
        return tuple(candidates.values())


def _matching_services(state: VectorState, requirements: tuple) -> tuple[ServiceFact, ...]:
    service_requirements = tuple(requirement for requirement in requirements if requirement.entity in {"service", "port"})
    if not service_requirements:
        return ()
    matches = state.matches(service_requirements[0])
    for requirement in service_requirements[1:]:
        allowed = {service.identity for service in state.matches(requirement)}
        matches = tuple(service for service in matches if service.identity in allowed)
    return matches


def _candidate_for(capability, target: str, reason: tuple[str, ...], sources: tuple[str, ...]) -> Candidate:
    return Candidate(capability.identity, capability.intent, target, reason, tuple(sorted(sources)))


def _add_candidate(candidates: dict[str, Candidate], candidate: Candidate, completed: frozenset[str]) -> None:
    if candidate.identity not in completed:
        candidates.setdefault(candidate.identity, candidate)
