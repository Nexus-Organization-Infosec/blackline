"""Provider-neutral facts exchanged between planning and execution steps."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable


@dataclass(frozen=True, slots=True)
class Artifact:
    """One immutable observation with explicit provenance."""

    kind: str
    subject: str
    data: dict[str, object] = field(default_factory=dict)
    source_step: str = ""
    source_provider: str = ""
    confidence: float | None = None
    observed_at: str = ""
    schema_version: int = 1

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ArtifactStore:
    """Deterministic in-memory artifact collection for one plan execution."""

    def __init__(self, artifacts: Iterable[Artifact] = ()) -> None:
        self._artifacts: list[Artifact] = []
        self._identities: set[tuple[object, ...]] = set()
        self.extend(artifacts)

    def add(self, artifact: Artifact) -> bool:
        identity = _artifact_identity(artifact)
        if identity in self._identities:
            return False
        self._identities.add(identity)
        self._artifacts.append(artifact)
        return True

    def extend(self, artifacts: Iterable[Artifact]) -> None:
        for artifact in artifacts:
            self.add(artifact)

    def find(
        self,
        kind: str,
        *,
        subject: str = "",
        source_provider: str = "",
    ) -> tuple[Artifact, ...]:
        return tuple(
            artifact
            for artifact in self._artifacts
            if artifact.kind == kind
            and (not subject or artifact.subject == subject)
            and (not source_provider or artifact.source_provider == source_provider)
        )

    def has(self, kind: str) -> bool:
        return any(artifact.kind == kind for artifact in self._artifacts)

    def snapshot(self) -> "ArtifactStore":
        return ArtifactStore(self._artifacts)

    def all(self) -> tuple[Artifact, ...]:
        return tuple(self._artifacts)

    def __len__(self) -> int:
        return len(self._artifacts)


def _artifact_identity(artifact: Artifact) -> tuple[object, ...]:
    return (
        artifact.kind,
        artifact.subject,
        _freeze(artifact.data),
        artifact.source_step,
        artifact.source_provider,
    )


def _freeze(value: object) -> object:
    if isinstance(value, dict):
        return tuple(sorted((str(key), _freeze(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set):
        return tuple(sorted((_freeze(item) for item in value), key=repr))
    return value
