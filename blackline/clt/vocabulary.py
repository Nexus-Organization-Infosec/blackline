"""Small, extensible semantic vocabulary for CLT."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class WordClass(str, Enum):
    """The role a word may play in a CLT semantic phrase."""

    ACTION = "action"
    ENTITY = "entity"
    STATE = "state"
    STRATEGY = "strategy"
    DOMAIN = "domain"
    CONTROL = "control"


_CORE_WORDS: dict[WordClass, frozenset[str]] = {
    WordClass.CONTROL: frozenset({"if", "else"}),
    WordClass.ACTION: frozenset({"recon", "scan", "inspect", "analyze", "collect", "report", "save", "load"}),
    WordClass.ENTITY: frozenset({"target", "host", "service", "port", "result", "finding", "evidence", "protocol", "version"}),
    WordClass.STATE: frozenset({"open", "closed", "found", "missing", "true", "false"}),
    WordClass.STRATEGY: frozenset({"fast", "balanced", "deep"}),
    WordClass.DOMAIN: frozenset({"ssh", "http", "https", "tls", "web"}),
}


@dataclass(slots=True)
class Vocabulary:
    """Vocabulary with a fixed language core and registered domain words."""

    words: dict[WordClass, set[str]] = field(default_factory=lambda: {kind: set(values) for kind, values in _CORE_WORDS.items()})

    def register(self, word: str, word_class: WordClass) -> None:
        """Register a plugin-supplied semantic word."""
        normalized = word.strip().lower()
        if not normalized or not normalized.replace("-", "").isalnum():
            raise ValueError("CLT vocabulary words must be non-empty alphanumeric terms")
        self.words.setdefault(word_class, set()).add(normalized)

    def has(self, word: str, *classes: WordClass) -> bool:
        """Return whether a word belongs to any requested semantic class."""
        normalized = word.lower()
        chosen = classes or tuple(self.words)
        return any(normalized in self.words.get(word_class, set()) for word_class in chosen)

    def classify(self, word: str) -> frozenset[WordClass]:
        """Return every semantic class registered for a word."""
        normalized = word.lower()
        return frozenset(kind for kind, values in self.words.items() if normalized in values)

    def choices(self) -> tuple[str, ...]:
        """Return all known words in stable order for diagnostics."""
        return tuple(sorted({word for values in self.words.values() for word in values}))

    def copy(self) -> Vocabulary:
        """Return an independent vocabulary, useful for one plugin/runtime."""
        return Vocabulary({kind: set(values) for kind, values in self.words.items()})


def default_vocabulary() -> Vocabulary:
    """Return the standard CLT v0 vocabulary."""
    return Vocabulary()
