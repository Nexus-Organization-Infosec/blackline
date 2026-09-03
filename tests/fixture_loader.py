"""Helpers for loading sanitized parser fixtures."""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).with_name("fixtures")


def read_text(*parts: str) -> str:
    return (FIXTURES.joinpath(*parts)).read_text(encoding="utf-8")


def read_json(*parts: str) -> dict:
    return json.loads(read_text(*parts))
