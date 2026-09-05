"""Semantic validation for CLT syntax trees and normalized workflows."""

from __future__ import annotations

from blackline.clt.ast import AssignmentNode, ConditionNode, FlowNode, ModuleNode, OperationNode, StatementNode
from blackline.clt.errors import ValidationError, unknown_word_error
from blackline.clt.normalize import normalize_action, normalize_condition
from blackline.clt.vocabulary import Vocabulary, WordClass


def validate(module: ModuleNode, vocabulary: Vocabulary) -> None:
    """Validate vocabulary, phrase meaning, and workflow block constraints."""
    _validate_block(module.statements, vocabulary, top_level=True)


def _validate_block(statements: tuple[StatementNode, ...], vocabulary: Vocabulary, *, top_level: bool) -> None:
    for statement in statements:
        if isinstance(statement, AssignmentNode):
            continue
        if isinstance(statement, OperationNode):
            _validate_action_word(statement.name, statement.location, vocabulary)
            names: set[str] = set()
            for argument in statement.arguments:
                if argument.name:
                    normalized = argument.name.lower()
                    if normalized in names:
                        raise ValidationError(f"duplicate operation option '{argument.name}'", argument.location)
                    names.add(normalized)
            _validate_block(statement.body, vocabulary, top_level=False)
            continue
        if isinstance(statement, FlowNode):
            normalize_action(statement.phrase, vocabulary)
            continue
        if isinstance(statement, ConditionNode):
            normalize_condition(statement.phrase, vocabulary)
            _validate_block(statement.body, vocabulary, top_level=False)
            _validate_block(statement.else_body, vocabulary, top_level=False)
            continue
        raise ValidationError("unsupported CLT statement")


def _validate_action_word(word: str, location: object, vocabulary: Vocabulary) -> None:
    if vocabulary.has(word, WordClass.ACTION):
        return
    # Operations are action words; plugins explicitly register new ones here.
    if hasattr(location, "line"):
        raise unknown_word_error(word, location, vocabulary.choices())
    raise ValidationError(f"unknown operation '{word}'")
