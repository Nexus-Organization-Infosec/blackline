"""Syntax-only abstract syntax tree for CLT."""

from __future__ import annotations

from dataclasses import dataclass, field

from blackline.clt.errors import SourceLocation


@dataclass(frozen=True, slots=True)
class ValueNode:
    """A literal or named-value reference as written in source."""

    value: str
    quoted: bool
    location: SourceLocation


@dataclass(frozen=True, slots=True)
class ArgumentNode:
    """A positional or named operation argument."""

    value: ValueNode
    name: str = ""
    location: SourceLocation | None = None


@dataclass(frozen=True, slots=True)
class AssignmentNode:
    name: str
    value: ValueNode
    location: SourceLocation


@dataclass(frozen=True, slots=True)
class OperationNode:
    name: str
    arguments: tuple[ArgumentNode, ...]
    body: tuple[StatementNode, ...] = field(default_factory=tuple)
    location: SourceLocation | None = None


@dataclass(frozen=True, slots=True)
class FlowNode:
    phrase: tuple[ValueNode, ...]
    location: SourceLocation


@dataclass(frozen=True, slots=True)
class ConditionNode:
    phrase: tuple[ValueNode, ...]
    body: tuple[StatementNode, ...] = field(default_factory=tuple)
    else_body: tuple[StatementNode, ...] = field(default_factory=tuple)
    location: SourceLocation | None = None


StatementNode = AssignmentNode | OperationNode | FlowNode | ConditionNode


@dataclass(frozen=True, slots=True)
class ModuleNode:
    statements: tuple[StatementNode, ...]
    filename: str = "<memory>"
