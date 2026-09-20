"""Identity and version validation for discovered executables."""

from __future__ import annotations

import re
from typing import Callable

from blackline.pathfinder.models import ToolSpec
from blackline.utils.exec import CommandResult, run_command

CommandRunner = Callable[[tuple[str, ...], float], CommandResult]


def validate_candidate(candidate: str, spec: ToolSpec, *, command_runner: CommandRunner, timeout_seconds: float) -> tuple[bool, str, str]:
    """Run a bounded identity check and return validity, version, and detail."""
    result = command_runner((candidate, *spec.check_args), timeout_seconds)
    output = (result.stdout or result.stderr or "").strip()
    version = version_from_output(output)
    if result.returncode in spec.check_success_codes and matches_identity(output, spec.identity_markers):
        return (True, version, "identity check passed")
    return (False, version, failure_detail(result, spec))


def run_version_probe(command: tuple[str, ...], timeout_seconds: float) -> CommandResult:
    """Run one non-network version or identity command."""
    return run_command(command, timeout=timeout_seconds)


def matches_identity(output: str, markers: tuple[str, ...]) -> bool:
    """Require every configured marker so similarly named tools are rejected."""
    normalized = " ".join(output.lower().split())
    return not markers or all(marker in normalized for marker in markers)


def version_from_output(output: str) -> str:
    """Extract a compact, terminal-code-free version line for user-facing status."""
    lines = [strip_terminal_codes(line).strip() for line in output.splitlines() if line.strip()]
    current = next((line for line in lines if "current version" in line.lower()), "")
    return current[:120] if current else (lines[0][:120] if lines else "unknown")


def failure_detail(result: CommandResult, spec: ToolSpec) -> str:
    """Describe a failed identity check without exposing noisy command output."""
    output = " ".join((result.stdout or result.stderr or "").split())
    if result.returncode not in spec.check_success_codes:
        return f"identity check exited {result.returncode}: {output[:100]}".rstrip(": ")
    if spec.identity_markers:
        return f"does not match the expected {spec.provider or spec.name} implementation"
    return "identity check failed"


def strip_terminal_codes(value: str) -> str:
    """Remove ANSI colour/style codes emitted by some third-party tools."""
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
