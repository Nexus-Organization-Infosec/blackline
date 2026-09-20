"""Executable discovery for Pathfinder."""

from __future__ import annotations

import os
from pathlib import Path
from shutil import which
from typing import Callable

ExecutableResolver = Callable[[str], str | None]


def discover_candidates(
    executable: str,
    *,
    executable_resolver: ExecutableResolver = which,
    path_entries: Callable[[], list[str]] = os.get_exec_path,
) -> tuple[str, ...]:
    """Find every executable candidate without assuming the first PATH hit wins."""
    path = Path(executable).expanduser()
    if path.parent != Path("."):
        return (str(path),) if _is_executable(path) else ()

    candidates: list[str] = []
    preferred = executable_resolver(executable)
    if preferred:
        candidates.append(preferred)
    for directory in path_entries():
        candidate = Path(directory) / executable
        if _is_executable(candidate):
            candidates.append(str(candidate))
    managed_bin = Path(os.environ.get("BLACKLINE_TOOL_BIN", Path.home() / ".local" / "bin"))
    candidate = managed_bin / executable
    if _is_executable(candidate):
        candidates.append(str(candidate))
    return tuple(dict.fromkeys(candidates))


def _is_executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)
