# frontend/parser/intent_parser.py

import re
from typing import Dict, Any

from config.frontend.frontend_config import get_operators
from frontend.parser.recon_parser import parse_recon_entities


COMMAND_PATTERN = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_]*)")


def parse_intent(line: str) -> Dict[str, Any]:

    intent = {
        "raw": line,
        "action": None,
        "entities": {},
        "operators": [],
        "errors": [],
    }

    text = (line or "").strip()
    if not text:
        intent["errors"].append("Empty command")
        return intent

    operators = _get_operator_definitions()
    remaining = text

    for operator in operators:
        symbol = operator["symbol"]
        while symbol in remaining:
            intent["operators"].append({
                "symbol": symbol,
                "name": operator["name"],
            })
            remaining = remaining.replace(symbol, " ", 1)

    remaining = remaining.strip()

    match = COMMAND_PATTERN.match(remaining)
    if not match:
        intent["errors"].append("Invalid or missing command name")
        return intent

    action = match.group(1).lower()
    intent["action"] = action

    if action == "recon":
        entities, errors = parse_recon_entities(remaining)
        intent["entities"] = entities
        intent["errors"].extend(errors)

    return intent


def _get_operator_definitions() -> list[dict[str, str]]:
    """Return operators in longest-symbol-first order for deterministic parsing."""
    definitions: list[dict[str, str]] = []

    for operator in get_operators():
        if not isinstance(operator, dict):
            continue

        symbol = operator.get("symbol")
        if not symbol:
            continue

        definitions.append({
            "symbol": str(symbol),
            "name": str(operator.get("name") or symbol),
        })

    return sorted(definitions, key=lambda op: len(op["symbol"]), reverse=True)
