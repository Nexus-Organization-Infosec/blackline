"""Deterministic semantic normalization for compact CLT phrases."""

from __future__ import annotations

from blackline.clt.ast import ValueNode
from blackline.clt.errors import NormalizationError
from blackline.clt.ir import ActionIntent, ConditionIntent
from blackline.clt.vocabulary import Vocabulary, WordClass


def normalize_condition(phrase: tuple[ValueNode, ...], vocabulary: Vocabulary) -> ConditionIntent:
    """Normalize an unambiguous ENTITY + VALUE + STATE condition phrase."""
    entities = _words_of(phrase, vocabulary, WordClass.ENTITY)
    states = _words_of(phrase, vocabulary, WordClass.STATE)
    if len(entities) != 1 or len(states) != 1:
        raise NormalizationError(
            "a condition needs exactly one entity and one state",
            phrase[0].location,
            "example: if port 22 open",
        )
    entity = entities[0].value.lower()
    state = states[0].value.lower()
    remaining = [word for word in phrase if word not in entities and word not in states]
    if entity == "port":
        numbers = [word for word in remaining if word.value.isdigit()]
        if not numbers:
            raise NormalizationError("a port number is required", phrase[0].location, "example: if port 22 open")
        if len(numbers) != 1 or len(remaining) != 1:
            raise NormalizationError("ambiguous expression", phrase[0].location, "a port condition needs exactly one port number")
        port = int(numbers[0].value)
        if not 1 <= port <= 65535:
            raise NormalizationError("port numbers must be between 1 and 65535", numbers[0].location)
        return ConditionIntent(entity="port", value=str(port), state=state, location=phrase[0].location)
    if entity == "service":
        domains = [word for word in remaining if vocabulary.has(word.value, WordClass.DOMAIN)]
        if len(domains) != 1 or len(remaining) != 1:
            raise NormalizationError(
                "a service condition requires exactly one registered protocol",
                phrase[0].location,
                "example: if service http found",
            )
        return ConditionIntent(entity="service", value=domains[0].value.lower(), state=state, location=phrase[0].location)
    if len(remaining) != 1:
        raise NormalizationError("ambiguous expression", phrase[0].location, "rewrite the condition with one value")
    return ConditionIntent(entity=entity, value=remaining[0].value, state=state, location=phrase[0].location)


def normalize_action(phrase: tuple[ValueNode, ...], vocabulary: Vocabulary) -> ActionIntent:
    """Normalize a simple action phrase while allowing safe word reordering."""
    actions = _words_of(phrase, vocabulary, WordClass.ACTION)
    if len(actions) != 1:
        raise NormalizationError("an action needs exactly one operation word", phrase[0].location)
    verb = actions[0].value.lower()
    subjects = [word for word in phrase if word is not actions[0]]
    if not subjects:
        return ActionIntent(verb=verb, location=phrase[0].location)
    if len(subjects) != 1:
        raise NormalizationError("ambiguous expression", phrase[0].location, "an action can name only one subject")
    subject = subjects[0]
    if not vocabulary.has(subject.value, WordClass.DOMAIN, WordClass.ENTITY):
        raise NormalizationError(f"unknown action subject '{subject.value}'", subject.location)
    return ActionIntent(verb=verb, subject=subject.value.lower(), location=phrase[0].location)


def _words_of(phrase: tuple[ValueNode, ...], vocabulary: Vocabulary, word_class: WordClass) -> list[ValueNode]:
    return [word for word in phrase if vocabulary.has(word.value, word_class)]
