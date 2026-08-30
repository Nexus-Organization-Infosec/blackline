"""Common shell utility commands."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from blackline import __version__
from blackline.cli.ui.display import info, result, warn, write_line
from blackline.storage.history_store import append_history, clear_history, load_history


@dataclass(slots=True)
class ShellState:
    """Mutable state owned by one interactive shell session."""

    history: list[str] = field(default_factory=list)
    active_job: str = ""
    history_path: Path | None = None
    prompt_session: Any | None = None
    sudo_authenticated: bool = False
    sudo_expires_at: float = 0.0


def handle_clear() -> None:
    """Clear the terminal using ANSI control codes."""
    print("\033[2J\033[H", end="")


def handle_version(*, use_color: bool | None = None) -> None:
    """Render Blackline version info."""
    result(f"blackline v{_short_version(__version__)}", use_color=use_color)


def handle_history(state: ShellState, *, show_all: bool = False, use_color: bool | None = None) -> None:
    """Render persisted command history."""
    entries = load_history(history_path=state.history_path, include_filtered=show_all)
    if not entries:
        info("history is empty", use_color=use_color)
        return

    width = len(str(len(entries)))
    for index, entry in enumerate(entries, start=1):
        write_line(f"{str(index).rjust(width)}  {entry.command}", color="muted", use_color=use_color)


def handle_reset(state: ShellState, *, use_color: bool | None = None) -> None:
    """Reset lightweight shell state."""
    state.history.clear()
    state.sudo_authenticated = False
    state.sudo_expires_at = 0.0
    result("session state reset", use_color=use_color)


def handle_history_clear(state: ShellState, *, use_color: bool | None = None) -> None:
    """Clear persisted and in-memory history."""
    state.history.clear()
    clear_history(history_path=state.history_path)
    result("history cleared", use_color=use_color)


def handle_placeholder(command: str, *, use_color: bool | None = None) -> None:
    """Render a clear message for configured commands not implemented yet."""
    warn(f"{command} is planned but not wired to the engine yet", use_color=use_color)


def record_history(state: ShellState, command: str) -> None:
    """Record one command in session and persistent history."""
    state.history.append(command)
    append_history(command, history_path=state.history_path)


def _short_version(version: str) -> str:
    parts = version.split(".")
    if len(parts) >= 2:
        return ".".join(parts[:2])
    return version
