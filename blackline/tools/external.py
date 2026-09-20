"""Small shared helpers for external command adapters."""

from __future__ import annotations

from typing import Callable

from blackline.pathfinder import require_tool
from blackline.utils.exec import CommandResult

CommandExecutor = Callable[[tuple[str, ...]], CommandResult]


def configured_flags(config: dict, *, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Return normalized command flags without leaking malformed config values."""
    raw = config.get("flags", default)
    if not isinstance(raw, list):
        return default
    return tuple(str(flag) for flag in raw)


def resolve_external_binary(tool: str, binary: str, executor: CommandExecutor | None) -> tuple[str, str]:
    """Return the verified executable for a real run, preserving test injection.

    Adapters receive an absolute, fingerprinted path in production.  An
    injected executor intentionally keeps its requested binary so command
    contract tests do not require installed third-party tools.
    """
    if executor is not None:
        return (binary, "")
    resolution = require_tool(tool, executable=binary)
    return (resolution.path, "") if resolution.valid else ("", resolution.detail)
