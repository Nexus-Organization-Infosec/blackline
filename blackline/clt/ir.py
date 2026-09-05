"""Normalized, runtime-independent representation of CLT workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeAlias

from blackline.clt.errors import SourceLocation


@dataclass(frozen=True, slots=True)
class ActionIntent:
    """Capability-oriented operation intent."""

    verb: str
    subject: str = ""
    location: SourceLocation | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class ConditionIntent:
    """A normalized fact condition such as PORT_OPEN(22)."""

    entity: str
    value: str
    state: str
    location: SourceLocation | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class IRAssignment:
    name: str
    value: str
    location: SourceLocation | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class IROperation:
    intent: ActionIntent
    inputs: tuple[str, ...] = field(default_factory=tuple)
    options: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    body: tuple[IRStatement, ...] = field(default_factory=tuple)
    location: SourceLocation | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class IRFlow:
    intent: ActionIntent
    location: SourceLocation | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class IRRule:
    condition: ConditionIntent
    body: tuple[IRStatement, ...]
    else_body: tuple[IRStatement, ...] = field(default_factory=tuple)
    location: SourceLocation | None = field(default=None, compare=False)


IRStatement: TypeAlias = IRAssignment | IROperation | IRFlow | IRRule


@dataclass(frozen=True, slots=True)
class WorkflowIR:
    """Compiled CLT program safe for deterministic runtime execution."""

    statements: tuple[IRStatement, ...]
    filename: str = "<memory>"
