"""Recursive-descent parser for the compact CLT grammar."""

from __future__ import annotations

from blackline.clt.ast import ArgumentNode, AssignmentNode, ConditionNode, FlowNode, ModuleNode, OperationNode, StatementNode, ValueNode
from blackline.clt.errors import ParseError
from blackline.clt.tokens import Token, TokenKind


class Parser:
    """Parse a stream of CLT tokens into syntax nodes only."""

    def __init__(self, tokens: tuple[Token, ...], *, filename: str = "<memory>") -> None:
        self.tokens = tokens
        self.filename = filename
        self.index = 0

    def parse(self) -> ModuleNode:
        statements = self._block(stop_at=TokenKind.EOF)
        self._expect(TokenKind.EOF)
        return ModuleNode(tuple(statements), filename=self.filename)

    def _block(self, *, stop_at: TokenKind) -> list [StatementNode]:
        statements: list[StatementNode] = []
        while not self._at(stop_at):
            if self._match(TokenKind.NEWLINE):
                continue
            if self._at(TokenKind.DEDENT): 
                if stop_at is TokenKind.DEDENT: 
                    break 
                raise ParseError("unexpected indentation decrease", self._current(). location)
            statements.append(self._statement())
        return statements

    def _statement(self) -> StatementNode:
        if self._match(TokenKind.ARROW):
            arrow = self._previous()
            phrase = self._phrase_until_newline()
            if not phrase:
                raise ParseError("a flow must name a next operation", arrow.location)
            self._expect(TokenKind.NEWLINE)
            return FlowNode(tuple(phrase), arrow.location)

        first = self._expect(TokenKind.IDENTIFIER, "expected an assignment, operation, or condition")
        if first.value.lower() == "if":
            phrase = self._phrase_until_newline()
            if not phrase:
                raise ParseError("an if statement requires a condition", first.location)
            self._expect(TokenKind.NEWLINE)
            body = self._required_block("an if statement requires an indented block", first)
            else_body: list[StatementNode] = []
            if self._at(TokenKind.IDENTIFIER) and self._current().value.lower() == "else":
                otherwise = self._advance()
                self._expect(TokenKind.NEWLINE, "else must end at the end of its line")
                else_body = self._required_block("an else statement requires an indented block", otherwise)
            return ConditionNode(tuple(phrase), tuple(body), tuple(else_body), first.location)

        if self._match(TokenKind.EQUALS):
            value = self._value(self._current())
            self._advance()
            self._expect(TokenKind.NEWLINE)
            return AssignmentNode(first.value, value, first.location)

        arguments: list[ArgumentNode] = []
        if self._match(TokenKind.LBRACKET):
            arguments = self._arguments()
            self._expect(TokenKind.RBRACKET, "expected ']' after operation inputs")
        self._expect(TokenKind.NEWLINE, "an operation must end at the end of its line")
        body: list[StatementNode] = []
        if self._match(TokenKind.INDENT):
            body = self._block(stop_at=TokenKind.DEDENT)
            self._expect(TokenKind.DEDENT)
        return OperationNode(first.value, tuple(arguments), tuple(body), first.location)

    def _required_block(self, message: str, token: Token) -> list[StatementNode]:
        if not self._match(TokenKind.INDENT):
            raise ParseError(message, token.location)
        body = self._block(stop_at=TokenKind.DEDENT)
        if not body:
            raise ParseError(message, token.location)
        self._expect(TokenKind.DEDENT)
        return body

    def _arguments(self) -> list[ArgumentNode]:
        arguments: list[ArgumentNode] = []
        if self._at(TokenKind.RBRACKET):
            return arguments
        while True:
            first = self._current()
            value = self._value(first)
            self._advance()
            if self._match(TokenKind.EQUALS):
                named_value = self._value(self._current())
                self._advance()
                arguments.append(ArgumentNode(named_value, name=value.value, location=first.location))
            else:
                arguments.append(ArgumentNode(value, location=first.location))
            if not self._match(TokenKind.COMMA):
                return arguments
            if self._at(TokenKind.RBRACKET):
                raise ParseError("an operation input is required after ','", self._current().location)

    def _phrase_until_newline(self) -> list[ValueNode]:
        phrase: list[ValueNode] = []
        while not self._at(TokenKind.NEWLINE) and not self._at(TokenKind.EOF):
            phrase.append(self._value(self._current()))
            self._advance()
        return phrase

    @staticmethod
    def _value(token: Token) -> ValueNode:
        if token.kind not in {TokenKind.IDENTIFIER, TokenKind.NUMBER, TokenKind.STRING, TokenKind.IP_ADDRESS}:
            raise ParseError("expected a word or literal", token.location)
        return ValueNode(token.value, quoted=token.kind is TokenKind.STRING, location=token.location)

    def _expect(self, kind: TokenKind, message: str = "") -> Token:
        if not self._at(kind):
            expected = message or f"expected {kind.value.lower()}"
            raise ParseError(expected, self._current().location)
        return self._advance()

    def _match(self, kind: TokenKind) -> bool:
        if not self._at(kind):
            return False
        self._advance()
        return True

    def _at(self, kind: TokenKind) -> bool:
        return self._current().kind is kind

    def _current(self) -> Token:
        return self.tokens[self.index]

    def _previous(self) -> Token:
        return self.tokens[self.index - 1]

    def _advance(self) -> Token:
        token = self.tokens[self.index]
        self.index += 1
        return token


def parse(tokens: tuple[Token, ...], *, filename: str = "<memory>") -> ModuleNode:
    """Parse CLT tokens into a module syntax tree."""
    return Parser(tokens, filename=filename).parse()
