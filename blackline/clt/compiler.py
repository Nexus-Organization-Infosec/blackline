"""Compile CLT source through lexing, parsing, validation, and IR generation."""

from __future__ import annotations

from blackline.clt.ast import AssignmentNode, ConditionNode, FlowNode, ModuleNode, OperationNode, StatementNode
from blackline.clt.ir import IRAssignment, IRFlow, IROperation, IRRule, IRStatement, WorkflowIR
from blackline.clt.lexer import lex
from blackline.clt.normalize import normalize_action, normalize_condition
from blackline.clt.parser import parse
from blackline.clt.validator import validate
from blackline.clt.vocabulary import Vocabulary, default_vocabulary


def compile_source(source: str, *, filename: str = "<memory>", vocabulary: Vocabulary | None = None) -> WorkflowIR:
    """Compile CLT source text into normalized workflow IR."""
    vocabulary = vocabulary or default_vocabulary()
    module = parse(lex(source, filename=filename), filename=filename)
    validate(module, vocabulary)
    return compile_module(module, vocabulary)


def compile_module(module: ModuleNode, vocabulary: Vocabulary) -> WorkflowIR:
    """Compile a previously parsed and validated CLT module."""
    return WorkflowIR(tuple(_compile_statement(statement, vocabulary) for statement in module.statements), filename=module.filename)


def _compile_statement(statement: StatementNode, vocabulary: Vocabulary) -> IRStatement:
    if isinstance(statement, AssignmentNode):
        return IRAssignment(statement.name, statement.value.value, statement.location)
    if isinstance(statement, OperationNode):
        inputs = tuple(argument.value.value for argument in statement.arguments if not argument.name)
        options = tuple((argument.name, argument.value.value) for argument in statement.arguments if argument.name)
        return IROperation(
            intent=normalize_action((_operation_value(statement),), vocabulary),
            inputs=inputs,
            options=options,
            body=tuple(_compile_statement(child, vocabulary) for child in statement.body),
            location=statement.location,
        )
    if isinstance(statement, FlowNode):
        return IRFlow(normalize_action(statement.phrase, vocabulary), statement.location)
    if isinstance(statement, ConditionNode):
        return IRRule(
            normalize_condition(statement.phrase, vocabulary),
            tuple(_compile_statement(child, vocabulary) for child in statement.body),
            tuple(_compile_statement(child, vocabulary) for child in statement.else_body),
            statement.location,
        )
    raise TypeError(f"unsupported CLT statement: {type(statement).__name__}")


def _operation_value(statement: OperationNode):
    from blackline.clt.ast import ValueNode

    return ValueNode(statement.name, quoted=False, location=statement.location)  # type: ignore[arg-type]
