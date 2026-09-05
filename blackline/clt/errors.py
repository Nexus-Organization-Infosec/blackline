"""Human-readable diagnostics for the CLT language."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import get_close_matches


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """A precise location in a CLT source document."""

    line: int = 1
    column: int = 1
    source_line: str = ""
    filename: str = "<memory>"


class CLTError(ValueError):
    """Base error that renders a source-oriented CLT diagnostic."""

    title = "error"

    def __init__(self, message: str, location: SourceLocation | None = None, hint: str = "") -> None:
        self.message = message
        self.location = location
        self.hint = hint
        super().__init__(message)

    def __str__(self) -> str:
        lines = [f"[clt] {self.title}"]
        if self.location is not None:
            location = self.location
            lines.append(f"\n{location.filename}:{location.line}:{location.column}")
            if location.source_line:
                lines.append(f"\n    {location.source_line}")
                lines.append(f"    {' ' * max(location.column - 1, 0)}^")
        lines.append(f"\n{self.message}")
        if self.hint:
            lines.append(f"\n{self.hint}")
        return "\n".join(lines)


class LexError(CLTError):
    """Raised when source text cannot be tokenized."""

    title = "invalid syntax"


class ParseError(CLTError):
    """Raised when valid tokens do not form valid CLT syntax."""

    title = "invalid syntax"


class NormalizationError(CLTError):
    """Raised when a semantic phrase has zero or multiple meanings."""

    title = "invalid expression"


class ValidationError(CLTError):
    """Raised when a syntactically valid workflow violates CLT rules."""

    title = "validation error"


class CapabilityResolutionError(CLTError):
    """Raised when the runtime cannot resolve a requested capability."""

    title = "capability unavailable"


def unknown_word_error(word: str, location: SourceLocation, choices: tuple[str, ...]) -> ValidationError:
    """Build a consistent unknown-vocabulary diagnostic."""
    match = get_close_matches(word, choices, n=1, cutoff=0.6)
    hint = f"did you mean '{match[0]}'?" if match else "register the word through CLT domain vocabulary or rewrite it."
    return ValidationError(f"unknown word '{word}'", location, hint)
