"""Tool configuration loading helpers."""

from __future__ import annotations

import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

_REPORTED_CONFIG_ERRORS: set[str] = set()


@lru_cache(maxsize=1)
def load_tools_config() -> dict[str, Any]:
    """Load tool configuration from disk."""
    path = Path(__file__).resolve().parent / "tools.json"
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        _report_config_error(f"missing config: {path}")
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        _report_config_error(f"failed to load config {path}: {exc}")
        return {}
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


def _report_config_error(message: str) -> None:
    if message in _REPORTED_CONFIG_ERRORS:
        return
    _REPORTED_CONFIG_ERRORS.add(message)
    sys.__stderr__.write(f"\n[error] {message}\n")
    sys.__stderr__.flush()
