"""Capability metadata consumed by Vector rather than domain logic."""

from __future__ import annotations

from dataclasses import dataclass, field

from blackline.clt.ir import ActionIntent, ConditionIntent


@dataclass(frozen=True, slots=True)
class Capability:
    """One registered action Vector may propose for a matching target state."""

    intent: ActionIntent
    requirements: tuple[ConditionIntent, ...] = field(default_factory=tuple)
    cost: int = 1
    risk: int = 0
    priority: int = 0
    batch: bool = False
    goal_actions: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.intent.verb:
            raise ValueError("a Vector capability requires an action verb")
        if self.cost < 0 or self.risk < 0:
            raise ValueError("capability cost and risk cannot be negative")
        object.__setattr__(self, "goal_actions", frozenset(action.lower() for action in self.goal_actions))

    @property
    def identity(self) -> str:
        """Return the stable capability identifier used for deduplication."""
        return f"{self.intent.verb}:{self.intent.subject}".rstrip(":")

    @classmethod
    def for_action(
        cls,
        verb: str,
        subject: str = "",
        *,
        requires: tuple[ConditionIntent, ...] = (),
        **kwargs: object,
    ) -> Capability:
        """Build compact capability metadata without exposing CLT internals."""
        return cls(ActionIntent(verb.lower(), subject.lower()), requirements=requires, **kwargs)
