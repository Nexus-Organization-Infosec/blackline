"""A deterministic, indentation-aware lexer for CLT."""

from __future__ import annotations

import ipaddress
import re

from blackline.clt.errors import LexError, SourceLocation
from blackline.clt.tokens import Token, TokenKind

_WORD = re.compile(r"[^\s\[\],=#\-\>]+")


def lex(source: str, *, filename: str = "<memory>") -> tuple[Token, ...]:
    """Tokenize CLT source and make indentation explicit.

    CLT v0 uses exactly four spaces per indentation level.  Blank lines and
    comment-only lines are ignored, so they never affect a surrounding block.
    """
    tokens: list[Token] = []
    indents = [0]
    lines = source.splitlines()

    for line_number, original_line in enumerate(lines, start=1):
        line = _strip_comment(original_line)
        if not line.strip():
            continue
        if "\t" in line[: len(line) - len(line.lstrip(" \t"))]:
            raise LexError("tabs are not allowed for indentation; use four spaces", _location(filename, line_number, 1, original_line))

        content = line.lstrip(" ")
        indent = len(line) - len(content)
        if indent % 4:
            raise LexError("indentation must use multiples of four spaces", _location(filename, line_number, 1, original_line))
        if indent > indents[-1]:
            if indent != indents[-1] + 4:
                raise LexError("indentation may increase by only one level", _location(filename, line_number, 1, original_line))
            indents.append(indent)
            tokens.append(_token(TokenKind.INDENT, "", filename, line_number, 1, original_line))
        while indent < indents[-1]:
            indents.pop()
            tokens.append(_token(TokenKind.DEDENT, "", filename, line_number, 1, original_line))
        if indent != indents[-1]:
            raise LexError("indentation does not match an earlier block", _location(filename, line_number, 1, original_line))

        tokens.extend(_lex_line(content, filename=filename, line_number=line_number, column=indent + 1, source_line=original_line))
        tokens.append(_token(TokenKind.NEWLINE, "", filename, line_number, len(original_line) + 1, original_line))

    while len(indents) > 1:
        indents.pop()
        tokens.append(_token(TokenKind.DEDENT, "", filename, len(lines) + 1, 1, ""))
    tokens.append(_token(TokenKind.EOF, "", filename, len(lines) + 1, 1, ""))
    return tuple(tokens)


def _lex_line(content: str, *, filename: str, line_number: int, column: int, source_line: str) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    while index < len(content):
        character = content[index]
        current_column = column + index
        if character.isspace():
            index += 1
            continue
        if content.startswith("->", index):
            tokens.append(_token(TokenKind.ARROW, "->", filename, line_number, current_column, source_line))
            index += 2
            continue
        punctuation = {"=": TokenKind.EQUALS, "[": TokenKind.LBRACKET, "]": TokenKind.RBRACKET, ",": TokenKind.COMMA}
        if character in punctuation:
            tokens.append(_token(punctuation[character], character, filename, line_number, current_column, source_line))
            index += 1
            continue
        if character in {"'", '"'}:
            value, consumed = _read_string(content[index:], character, filename, line_number, current_column, source_line)
            tokens.append(_token(TokenKind.STRING, value, filename, line_number, current_column, source_line))
            index += consumed
            continue
        match = _WORD.match(content, index)
        if not match:
            raise LexError(f"unexpected character '{character}'", _location(filename, line_number, current_column, source_line))
        value = match.group(0)
        tokens.append(_token(_word_kind(value), value, filename, line_number, current_column, source_line))
        index = match.end()
    return tokens


def _strip_comment(line: str) -> str:
    quote = ""
    escaped = False
    for index, character in enumerate(line):
        if quote:
            if character == quote and not escaped:
                quote = ""
            escaped = character == "\\" and not escaped
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "#":
            return line[:index]
    return line


def _read_string(value: str, quote: str, filename: str, line_number: int, column: int, source_line: str) -> tuple[str, int]:
    escaped = False
    characters: list[str] = []
    for index, character in enumerate(value[1:], start=1):
        if character == quote and not escaped:
            return "".join(characters), index + 1
        if character == "\\" and not escaped:
            escaped = True
            continue
        characters.append(character)
        escaped = False
    raise LexError("unterminated string", _location(filename, line_number, column, source_line))


def _word_kind(value: str) -> TokenKind:
    if value.isdigit():
        return TokenKind.NUMBER
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return TokenKind.IDENTIFIER
    return TokenKind.IP_ADDRESS


def _location(filename: str, line: int, column: int, source_line: str) -> SourceLocation:
    return SourceLocation(line=line, column=column, source_line=source_line, filename=filename)


def _token(kind: TokenKind, value: str, filename: str, line: int, column: int, source_line: str) -> Token:
    return Token(kind, value, _location(filename, line, column, source_line))
