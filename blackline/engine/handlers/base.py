"""Handler contracts and explicitly injected tool services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from blackline.core.artifacts import Artifact, ArtifactStore
from blackline.engine.models import PlanStep, StepResult
from blackline.utils.exec import CommandResult

CommandExecutor = Callable[[tuple[str, ...]], CommandResult]
StepHandler = Callable[[PlanStep, "HandlerContext"], StepResult]


@dataclass(frozen=True, slots=True)
class HandlerContext:
    """Runtime inputs shared by all handlers."""

    command_executor: CommandExecutor | None = None
    artifacts: ArtifactStore | None = None

    @property
    def evidence(self) -> ArtifactStore:
        return self.artifacts if self.artifacts is not None else ArtifactStore()


def to_bool(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def to_port(value: object) -> int:
    try:
        port = int(str(value))
    except (TypeError, ValueError):
        return 443
    return port if 1 <= port <= 65535 else 443


def call_with_optional_timeout(function: Callable[..., Any], *args: object, timeout_seconds: float | None, **kwargs: object):
    """Call newer adapters with a timeout while supporting legacy injectors."""
    try:
        return function(*args, timeout_seconds=timeout_seconds, **kwargs)
    except TypeError:
        return function(*args, **kwargs)


def artifact(
    step: PlanStep,
    kind: str,
    subject: object,
    data: dict[str, object] | None = None,
    *,
    provider: str = "",
    confidence: float | None = None,
) -> Artifact:
    """Create one canonical artifact with consistent step provenance."""
    return Artifact(
        kind=kind,
        subject=str(subject).strip(),
        data=data or {},
        source_step=step.identity,
        source_provider=provider or step.tool,
        confidence=confidence,
    )
