"""Stable contracts shared by planning, execution, persistence, and presentation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, NewType

from blackline.core.recon.outcomes import classify_result, outcome_is_success
from blackline.core.artifacts import Artifact
from blackline.engine.context import ExecutionContext

if TYPE_CHECKING:
    from blackline.core.recon import ReconPipeline

StepId = NewType("StepId", str)
CapabilityId = NewType("CapabilityId", str)


class PlanValidationError(ValueError):
    """Raised when a plan's dependency contract is inconsistent."""


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded retry settings attached to one planned step."""

    max_attempts: int = 1
    backoff_seconds: float = 0.0
    retryable_outcomes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("retry max_attempts must be at least 1")
        if self.backoff_seconds < 0:
            raise ValueError("retry backoff_seconds cannot be negative")


@dataclass(frozen=True, slots=True)
class StepDependency:
    """One upstream step and the artifacts required from it."""

    step_id: StepId
    required_artifacts: tuple[str, ...] = ()
    optional: bool = False


@dataclass(frozen=True, slots=True)
class ExecutionEvent:
    """A versioned lifecycle event emitted by planning or execution."""

    kind: str
    data: dict[str, object] = field(default_factory=dict)
    job_id: str = ""
    step_id: str = ""
    created_at: str = ""
    schema_version: int = 1

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible event representation."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class StepResult:
    """Canonical outcome returned by every execution handler."""

    tool: str
    action: str
    ok: bool
    payload: dict[str, object]
    error: str = ""
    outcome: str = ""
    artifacts: tuple[Artifact, ...] = ()

    def __post_init__(self) -> None:
        payload = dict(self.payload)
        outcome = self.outcome or classify_result(
            tool=self.tool,
            ok=self.ok,
            payload=payload,
            error=self.error,
        )
        payload.setdefault("result_outcome", outcome)
        object.__setattr__(self, "payload", payload)
        object.__setattr__(self, "outcome", outcome)
        if outcome_is_success(outcome) and not self.ok:
            object.__setattr__(self, "ok", True)

    def to_dict(self) -> dict[str, object]:
        """Return a persistence-safe representation of the final result."""
        return {
            "tool": self.tool,
            "action": self.action,
            "ok": self.ok,
            "payload": dict(self.payload),
            "error": self.error,
            "outcome": self.outcome,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
        }


@dataclass(frozen=True, slots=True)
class PlanStep:
    """One executable step plus its provider-neutral planning contract.

    The first four fields intentionally preserve the original constructor so
    existing integrations can migrate without a flag day.
    """

    tool: str
    action: str
    params: dict[str, str] = field(default_factory=dict)
    execution_group: int = 0
    id: StepId | str = ""
    capability: CapabilityId | str = ""
    consumes: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    depends_on: tuple[StepDependency, ...] = ()
    reason: str = ""
    timeout_seconds: float | None = None
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    requires_elevation: bool = False

    @property
    def identity(self) -> str:
        """Return the explicit ID or a stable legacy-compatible fallback."""
        return str(self.id) or f"{self.tool}.{self.action}"

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible step representation."""
        return {
            "id": self.identity,
            "capability": str(self.capability),
            "provider": self.tool,
            "action": self.action,
            "inputs": dict(self.params),
            "execution_group": self.execution_group,
            "consumes": list(self.consumes),
            "produces": list(self.produces),
            "depends_on": [
                {
                    "step_id": str(dependency.step_id),
                    "required_artifacts": list(dependency.required_artifacts),
                    "optional": dependency.optional,
                }
                for dependency in self.depends_on
            ],
            "reason": self.reason,
            "timeout_seconds": self.timeout_seconds,
            "retry_policy": {
                "max_attempts": self.retry_policy.max_attempts,
                "backoff_seconds": self.retry_policy.backoff_seconds,
                "retryable_outcomes": list(self.retry_policy.retryable_outcomes),
            },
            "requires_elevation": self.requires_elevation,
        }


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """A deterministic, serializable collection of executable steps."""

    context: ExecutionContext
    steps: tuple[PlanStep, ...]
    pipeline: ReconPipeline | None = None
    id: str = ""
    schema_version: int = 1

    def validate(self) -> None:
        """Reject duplicate IDs, missing dependencies, and cycles."""
        from blackline.engine.graph import validate_plan_graph

        validate_plan_graph(self.steps)

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible plan representation."""
        target = self.context.normalized_target
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "context": {
                "expression": self.context.expression,
                "module": self.context.module,
                "params": dict(self.context.params),
                "job_id": self.context.job_id,
                "target": asdict(target) if target is not None else None,
            },
            "steps": [step.to_dict() for step in self.steps],
        }
