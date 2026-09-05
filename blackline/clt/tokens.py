"""Token types emitted by the CLT lexer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from blackline.clt.errors import SourceLocation


class TokenKind(str, Enum):
    """The deliberately small CLT token vocabulary."""

    IDENTIFIER = "IDENTIFIER"
    NUMBER = "NUMBER"
    STRING = "STRING"
    IP_ADDRESS = "IP_ADDRESS"
    ARROW = "ARROW"
    EQUALS = "EQUALS"
    LBRACKET = "LBRACKET"
    RBRACKET = "RBRACKET"
    COMMA = "COMMA"
    NEWLINE = "NEWLINE"
    INDENT = "INDENT"
    DEDENT = "DEDENT"
    EOF = "EOF"


@dataclass(frozen=True, slots=True)
class Token:
    """One lexical token together with its source location."""

    kind: TokenKind
    value: str
    location: SourceLocation
