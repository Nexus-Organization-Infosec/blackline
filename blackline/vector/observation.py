"""Structured observations entering Vector."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Mapping


@dataclass(frozen=True, slots=True)
class Observation:
    """One provenance-preserving fact emitted by a tool, plugin, or user."""

    kind: str
    data: Mapping[str, object]
    source: str
    confidence: float = 1.0
    identifier: str = ""

    def __post_init__(self) -> None:
        kind = self.kind.strip().lower()
        source = self.source.strip().lower()
        if not kind:
            raise ValueError("a Vector observation requires a kind")
        if not source:
            raise ValueError("a Vector observation requires a source")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("observation confidence must be between 0 and 1")
        normalized_data = {str(key).strip().lower(): value for key, value in self.data.items()}
        if not normalized_data:
            raise ValueError("a Vector observation requires structured data")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "data", normalized_data)
        if not self.identifier:
            digest_input = f"{kind}|{source}|{sorted((key, str(value)) for key, value in normalized_data.items())}"
            object.__setattr__(self, "identifier", sha256(digest_input.encode()).hexdigest()[:16])

    @classmethod
    def service(
        cls,
        *,
        host: str,
        port: int,
        protocol: str,
        state: str,
        source: str,
        transport: str = "tcp",
        confidence: float = 1.0,
        **details: object,
    ) -> Observation:
        """Create the common service observation shape used by Vector v0."""
        return cls(
            kind="service",
            data={
                "host": host,
                "port": int(port),
                "transport": transport.lower(),
                "protocol": protocol.lower(),
                "state": state.lower(),
                **details,
            },
            source=source,
            confidence=confidence,
        )
