"""Validation and deterministic wave construction for execution-plan DAGs."""

from __future__ import annotations

from collections import Counter
from typing import Sequence

from blackline.engine.models import PlanStep, PlanValidationError


def validate_plan_graph(steps: Sequence[PlanStep]) -> None:
    """Reject duplicate IDs, missing dependencies, and dependency cycles."""
    identities = tuple(step.identity for step in steps)
    duplicates = sorted(identity for identity, count in Counter(identities).items() if count > 1)
    if duplicates:
        raise PlanValidationError(f"duplicate plan step IDs: {', '.join(duplicates)}")

    known = set(identities)
    for step in steps:
        missing = sorted(
            str(dependency.step_id)
            for dependency in step.depends_on
            if str(dependency.step_id) not in known
        )
        if missing:
            raise PlanValidationError(
                f"step {step.identity} depends on unknown steps: {', '.join(missing)}"
            )
    dependency_waves(steps)


def dependency_waves(steps: Sequence[PlanStep]) -> tuple[tuple[int, ...], ...]:
    """Return stable topological waves as indexes into ``steps``."""
    remaining = list(range(len(steps)))
    completed: set[str] = set()
    waves: list[tuple[int, ...]] = []
    while remaining:
        ready = tuple(
            index
            for index in remaining
            if all(str(dependency.step_id) in completed for dependency in steps[index].depends_on)
        )
        if not ready:
            blocked = ", ".join(steps[index].identity for index in remaining)
            raise PlanValidationError(f"plan dependency cycle involving: {blocked}")
        waves.append(ready)
        ready_set = set(ready)
        remaining = [index for index in remaining if index not in ready_set]
        completed.update(steps[index].identity for index in ready)
    return tuple(waves)
