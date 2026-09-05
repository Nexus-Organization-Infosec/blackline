"""Goal models for Vector planning."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Goal:
    """The small, explicit direction supplied to one Vector instance."""

    action: str
    target: str
    strategy: str = "balanced"
    constraints: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        action = self.action.strip().lower()
        target = self.target.strip()
        strategy = self.strategy.strip().lower()
        if not action:
            raise ValueError("a Vector goal requires an action")
        if not target:
            raise ValueError("a Vector goal requires a target")
        if strategy not in {"fast", "balanced", "deep"}:
            raise ValueError("Vector strategy must be fast, balanced, or deep")
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "strategy", strategy)
