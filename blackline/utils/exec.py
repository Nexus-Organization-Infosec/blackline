"""Execution helpers."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Result of one subprocess execution."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    elapsed_seconds: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_command(args: Sequence[str], *, timeout: float | None = 30.0) -> CommandResult:
    """Run one command and capture stdout/stderr."""
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed_seconds = time.perf_counter() - started
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", errors="replace")
        message = stderr or f"command timed out after {timeout:.1f} seconds"
        return CommandResult(
            args=tuple(str(arg) for arg in args),
            returncode=124,
            stdout=stdout,
            stderr=message,
            elapsed_seconds=elapsed_seconds,
        )
    elapsed_seconds = time.perf_counter() - started
    return CommandResult(
        args=tuple(str(arg) for arg in args),
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        elapsed_seconds=elapsed_seconds,
    )
