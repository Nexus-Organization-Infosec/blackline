"""Small shared helpers for external command adapters."""

from __future__ import annotations

from shutil import which
from typing import Callable

from blackline.utils.exec import CommandResult

CommandExecutor = Callable[[tuple[str, ...]], CommandResult]


def configured_flags(config: dict, *, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Return normalized command flags without leaking malformed config values."""
    raw = config.get("flags", default)
    if not isinstance(raw, list):
        return default
    return tuple(str(flag) for flag in raw)


def executable_is_available(
    binary: str,
    executor: CommandExecutor | None,
    *,
    executable_resolver: Callable[[str], str | None] = which,
) -> bool:
    """Accept injected executors in tests; otherwise require a real executable."""
    return executor is not None or executable_resolver(binary) is not None
