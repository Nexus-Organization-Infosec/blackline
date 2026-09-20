"""Verified executable resolution for Pathfinder."""

from __future__ import annotations

import os
from shutil import which
from typing import Callable

from blackline.pathfinder.catalog import tool_spec
from blackline.pathfinder.discovery import ExecutableResolver, discover_candidates
from blackline.pathfinder.models import ToolResolution
from blackline.pathfinder.validation import CommandRunner, run_version_probe, validate_candidate


class Pathfinder:
    """Discover, fingerprint, validate, and resolve external Blackline tools."""

    def __init__(
        self,
        *,
        executable_resolver: ExecutableResolver = which,
        command_runner: CommandRunner | None = None,
        path_entries: Callable[[], list[str]] = os.get_exec_path,
        candidate_finder: Callable[[str], tuple[str, ...]] | None = None,
    ) -> None:
        self._executable_resolver = executable_resolver
        self._command_runner = command_runner or run_version_probe
        self._path_entries = path_entries
        self._candidate_finder = candidate_finder

    def require(self, name: str, *, executable: str = "", timeout_seconds: float = 3.0) -> ToolResolution:
        """Return the first verified implementation of a known tool."""
        spec = tool_spec(name, executable=executable)
        candidates = self._candidates(spec.executable)
        if not candidates:
            return ToolResolution(spec.name, spec.provider, detail=f"{spec.name} is unavailable")

        last_detail = ""
        last_version = ""
        for candidate in candidates:
            if not spec.check_args:
                return ToolResolution(spec.name, spec.provider, candidate, valid=True, detail="executable found", candidates=candidates)
            valid, version, detail = validate_candidate(
                candidate,
                spec,
                command_runner=self._command_runner,
                timeout_seconds=timeout_seconds,
            )
            if valid:
                return ToolResolution(spec.name, spec.provider, candidate, version, True, detail, candidates)
            last_version = version or last_version
            last_detail = detail

        return ToolResolution(
            spec.name,
            spec.provider,
            candidates[0],
            last_version,
            False,
            last_detail or f"no verified {spec.name} executable was found",
            candidates,
        )

    def locate(self, name: str, *, executable: str = "") -> ToolResolution:
        """Find candidate paths without executing a tool health probe."""
        spec = tool_spec(name, executable=executable)
        candidates = self._candidates(spec.executable)
        return ToolResolution(
            spec.name,
            spec.provider,
            candidates[0] if candidates else "",
            valid=False,
            detail="candidate found" if candidates else f"{spec.name} is unavailable",
            candidates=candidates,
        )

    def _candidates(self, executable: str) -> tuple[str, ...]:
        if self._candidate_finder is not None:
            return self._candidate_finder(executable)
        return discover_candidates(
            executable,
            executable_resolver=self._executable_resolver,
            path_entries=self._path_entries,
        )


def require_tool(name: str, *, executable: str = "", timeout_seconds: float = 3.0) -> ToolResolution:
    """Convenient process-wide entry point for adapters and commands."""
    return Pathfinder().require(name, executable=executable, timeout_seconds=timeout_seconds)
