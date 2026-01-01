# frontend/parser/recon_parser.py

import re
from typing import Dict, List, Tuple


RECON_BLOCK_PATTERN = re.compile(
    r"recon\s*\[(.*?)\]",
    re.IGNORECASE | re.DOTALL
)


def parse_recon_entities(text: str) -> Tuple[Dict[str, List[str]], List[str]]:
    entities: Dict[str, List[str]] = {}
    errors: List[str] = []

    match = RECON_BLOCK_PATTERN.search(text)
    if not match:
        errors.append("Missing recon[...] block")
        return entities, errors

    body = match.group(1).strip()
    if not body:
        errors.append("Empty recon entity list")
        return entities, errors

    parts = [p.strip() for p in body.split(",") if p.strip()]

    for part in parts:
        if "=" not in part:
            errors.append(f"Invalid entity syntax: '{part}'")
            continue

        key, value = part.split("=", 1)
        key = key.strip().lower()
        value = value.strip()

        if not key or not value:
            errors.append(f"Invalid entity pair: '{part}'")
            continue

        entities.setdefault(key, []).append(value)

    return entities, errors
