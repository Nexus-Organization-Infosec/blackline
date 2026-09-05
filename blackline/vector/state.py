"""Incremental structured state and narrow semantic indexes for Vector v0."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from blackline.clt.ir import ConditionIntent
from blackline.vector.observation import Observation


@dataclass(frozen=True, slots=True)
class ServiceFact:
    """Current contextual view of a discovered network service."""

    host: str
    port: int
    transport: str
    protocol: str
    state: str
    details: dict[str, object]
    sources: tuple[str, ...]
    observation_ids: tuple[str, ...]
    confidence: float

    @property
    def identity(self) -> tuple[str, int, str]:
        """Identity remains stable if a later observation improves protocol data."""
        return (self.host, self.port, self.transport)

    @property
    def target(self) -> str:
        """Compact endpoint representation used by per-service candidates."""
        return f"{self.host}:{self.port}"


@dataclass(frozen=True, slots=True)
class StateDelta:
    """The exact state area changed by one ingestion operation."""

    revision: int
    services: tuple[ServiceFact, ...] = field(default_factory=tuple)
    facts: tuple[tuple[str, str, str], ...] = field(default_factory=tuple)
    observation_ids: tuple[str, ...] = field(default_factory=tuple)

    @property
    def changed(self) -> bool:
        return bool(self.services or self.facts)


class VectorState:
    """State store that preserves provenance and indexes service observations."""

    def __init__(self) -> None:
        self.revision = 0
        self._services: dict[tuple[str, int, str], ServiceFact] = {}
        self._facts: dict[tuple[str, str], tuple[str, tuple[str, ...], tuple[str, ...], float]] = {}
        self._services_by_protocol: dict[str, set[tuple[str, int, str]]] = {}
        self._services_by_port: dict[int, set[tuple[str, int, str]]] = {}
        self._observations: dict[str, Observation] = {}

    @property
    def services(self) -> tuple[ServiceFact, ...]:
        """Return services in deterministic endpoint order."""
        return tuple(sorted(self._services.values(), key=lambda service: (service.host, service.port, service.transport)))

    def ingest(self, observations: Iterable[Observation]) -> StateDelta:
        """Apply observations and return only the facts changed by this update."""
        changed_services: list[ServiceFact] = []
        changed_facts: list[tuple[str, str, str]] = []
        observation_ids: list[str] = []
        for observation in observations:
            self._observations[observation.identifier] = observation
            observation_ids.append(observation.identifier)
            if observation.kind == "service":
                changed = self._ingest_service(observation)
                if changed is not None:
                    changed_services.append(changed)
                continue
            changed = self._ingest_fact(observation)
            if changed is not None:
                changed_facts.append(changed)
        if changed_services or changed_facts:
            self.revision += 1
        return StateDelta(self.revision, tuple(changed_services), tuple(changed_facts), tuple(observation_ids))

    def matches(self, condition: ConditionIntent) -> tuple[ServiceFact, ...]:
        """Use the narrowest index available to match a normalized condition."""
        entity, value, expected_state = condition.entity, condition.value, condition.state
        if entity == "service":
            candidates = self._services_for_protocol(value)
            return tuple(service for service in candidates if service.state == expected_state)
        if entity == "port" and value.isdigit():
            candidates = self._services_for_port(int(value))
            return tuple(service for service in candidates if service.state == expected_state)
        fact = self._facts.get((entity, value))
        return () if fact is None or fact[0] != expected_state else ()

    def holds(self, condition: ConditionIntent) -> bool:
        """Return whether any structured state fact proves a condition."""
        if condition.entity in {"service", "port"}:
            return bool(self.matches(condition))
        fact = self._facts.get((condition.entity, condition.value))
        return fact is not None and fact[0] == condition.state

    def condition_sources(self, condition: ConditionIntent) -> tuple[str, ...]:
        """Return the observation provenance proving a condition."""
        services = self.matches(condition)
        if services:
            return tuple(sorted({source for service in services for source in service.sources}))
        fact = self._facts.get((condition.entity, condition.value))
        return fact[1] if fact and fact[0] == condition.state else ()

    def _ingest_service(self, observation: Observation) -> ServiceFact | None:
        data = observation.data
        try:
            host = str(data["host"]).strip()
            port = int(data["port"])
            transport = str(data.get("transport", "tcp")).lower()
            protocol = str(data["protocol"]).lower()
            state = str(data["state"]).lower()
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("service observations require host, port, protocol, and state") from exc
        if not host or not protocol or not state or not 1 <= port <= 65535:
            raise ValueError("service observations contain invalid endpoint data")
        identity = (host, port, transport)
        existing = self._services.get(identity)
        details = dict(existing.details) if existing else {}
        details.update(data)
        sources = tuple(sorted(set((existing.sources if existing else ()) + (observation.source,))))
        observation_ids = tuple(sorted(set((existing.observation_ids if existing else ()) + (observation.identifier,))))
        confidence = max(existing.confidence if existing else 0.0, observation.confidence)
        service = ServiceFact(host, port, transport, protocol, state, details, sources, observation_ids, confidence)
        if existing == service:
            return None
        if existing:
            self._remove_service_indexes(existing)
        self._services[identity] = service
        self._services_by_protocol.setdefault(protocol, set()).add(identity)
        self._services_by_port.setdefault(port, set()).add(identity)
        return service

    def _ingest_fact(self, observation: Observation) -> tuple[str, str, str] | None:
        data = observation.data
        try:
            entity = str(data["entity"]).lower()
            value = str(data["value"]).lower()
            state = str(data["state"]).lower()
        except KeyError as exc:
            raise ValueError("non-service observations require entity, value, and state") from exc
        key = (entity, value)
        existing = self._facts.get(key)
        sources = tuple(sorted(set((existing[1] if existing else ()) + (observation.source,))))
        observation_ids = tuple(sorted(set((existing[2] if existing else ()) + (observation.identifier,))))
        confidence = max(existing[3] if existing else 0.0, observation.confidence)
        fact = (state, sources, observation_ids, confidence)
        if existing == fact:
            return None
        self._facts[key] = fact
        return entity, value, state

    def _services_for_protocol(self, protocol: str) -> tuple[ServiceFact, ...]:
        identities = self._services_by_protocol.get(protocol.lower(), set())
        return tuple(self._services[identity] for identity in sorted(identities))

    def _services_for_port(self, port: int) -> tuple[ServiceFact, ...]:
        identities = self._services_by_port.get(port, set())
        return tuple(self._services[identity] for identity in sorted(identities))

    def _remove_service_indexes(self, service: ServiceFact) -> None:
        self._services_by_protocol.get(service.protocol, set()).discard(service.identity)
        self._services_by_port.get(service.port, set()).discard(service.identity)
