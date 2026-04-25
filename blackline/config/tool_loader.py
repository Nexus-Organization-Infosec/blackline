"""Tool configuration loading helpers."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


@lru_cache(maxsize=1)
def load_tools_config() -> dict[str, Any]:
    """Load tool configuration from disk."""
    path = Path(__file__).resolve().parent / "tools.json"
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        return {}
    return data


def get_tool_config(name: str) -> dict[str, Any]:
    """Return configuration for one tool by name."""
    tools = load_tools_config().get("tools", {})
    config = tools.get(name, {})
    return config if isinstance(config, dict) else {}


def clear_tool_config_cache() -> None:
    """Clear cached tool configuration for tests/reloads."""
    load_tools_config.cache_clear()
