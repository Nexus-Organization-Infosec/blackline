# frontend/parser/intent_parser.py

import re
from typing import Dict, Any

from config.frontend.frontend_config import get_operator_symbols
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

    operator_symbols = get_operator_symbols()
    remaining = text

    for symbol in operator_symbols:
        while symbol in remaining:
            intent["operators"].append({
                "symbol": symbol
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
