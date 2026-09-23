"""Execution helpers."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Sequence


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


@dataclass(frozen=True, slots=True)
class CommandTraceEvent:
    """One command lifecycle event emitted for optional diagnostic output."""

    state: str
    args: tuple[str, ...]
    timeout: float | None
    cwd: Path | str | None = None
    result: CommandResult | None = None


CommandTraceCallback = Callable[[CommandTraceEvent], None]
_command_trace_callback: ContextVar[CommandTraceCallback | None] = ContextVar(
    "blackline_command_trace_callback",
    default=None,
)


@contextmanager
def trace_commands(callback: CommandTraceCallback | None) -> Iterator[None]:
    """Temporarily send command lifecycle events to ``callback``.

    The callback is diagnostic-only: a renderer error must never interrupt a
    scan or change a subprocess result.
    """
    token = _command_trace_callback.set(callback)
    try:
        yield
    finally:
        _command_trace_callback.reset(token)


def _emit_command_trace(event: CommandTraceEvent) -> None:
    callback = _command_trace_callback.get()
    if callback is None:
        return
    try:
        callback(event)
    except Exception:
        return


def run_command(
    args: Sequence[str],
    *,
    timeout: float | None = 30.0,
    input_text: str | None = None,
    cwd: Path | str | None = None,
) -> CommandResult:
    """Run one command and capture stdout/stderr."""
    normalized_args = tuple(str(arg) for arg in args)
    _emit_command_trace(CommandTraceEvent("started", normalized_args, timeout, cwd))
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            input=input_text,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed_seconds = time.perf_counter() - started
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", errors="replace")
        message = stderr or f"command timed out after {timeout:.1f} seconds"
        result = CommandResult(
            args=normalized_args,
            returncode=124,
            stdout=stdout,
            stderr=message,
            elapsed_seconds=elapsed_seconds,
        )
        _emit_command_trace(CommandTraceEvent("completed", normalized_args, timeout, cwd, result))
        return result
    except OSError as exc:
        elapsed_seconds = time.perf_counter() - started
        result = CommandResult(
            args=normalized_args,
            returncode=127,
            stdout="",
            stderr=str(exc),
            elapsed_seconds=elapsed_seconds,
        )
        _emit_command_trace(CommandTraceEvent("completed", normalized_args, timeout, cwd, result))
        return result
    elapsed_seconds = time.perf_counter() - started
    result = CommandResult(
        args=normalized_args,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        elapsed_seconds=elapsed_seconds,
    )
    _emit_command_trace(CommandTraceEvent("completed", normalized_args, timeout, cwd, result))
    return result
