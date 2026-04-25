"""Reusable UI elements."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from blackline import __version__
from blackline.cli.ui.colors import colorize
from blackline.cli.ui.display import write_line, write_segments


@dataclass(frozen=True, slots=True)
class StartupCheck:
    """One startup system-state check."""

    label: str
    path: str
    required: bool = True


@dataclass(frozen=True, slots=True)
class StartupCheckResult:
    """Result of one startup system-state check."""

    label: str
    ok: bool
    detail: str = ""


STARTUP_CHECKS = (
    StartupCheck("loading modules", "modules", required=False),
    StartupCheck("loading operators", "operators"),
    StartupCheck("loading tools", "tools"),
    StartupCheck("loading config", "config"),
    StartupCheck("initializing engine", "engine"),
)


def run_startup_checks(root: Path | None = None) -> list[StartupCheckResult]:
    """Check the high-level folders Blackline needs at startup."""
    root = root or Path(__file__).resolve().parents[2]
    results: list[StartupCheckResult] = []

    for check in STARTUP_CHECKS:
        path = root / check.path
        ok = path.exists()
        if ok or not check.required:
            results.append(StartupCheckResult(check.label, True))
        else:
            results.append(StartupCheckResult(check.label, False, f"missing {check.path}"))

    return results


def render_startup(results: list[StartupCheckResult], *, use_color: bool | None = None) -> None:
    """Render the Blackline startup banner and initialization checks."""
    write_segments(
        [
            ("[ ", "white"),
            ("blackline", "cyan"),
            (" ]", "white"),
        ],
        use_color=use_color,
    )
    write_line()
    write_line(f"version: v{_short_version(__version__)}", color="muted", use_color=use_color)
    write_line()
    write_line("initializing...", color="muted", use_color=use_color)

    for result in results:
        status = "ok" if result.ok else "fail"
        color = "green" if result.ok else "red"
        dots = "." * max(3, 25 - len(result.label))
        write_segments(
            [
                (result.label, "muted"),
                (f" {dots} ", "muted"),
                (status, color),
            ],
            use_color=use_color,
        )

    write_line()
    if all(result.ok for result in results):
        write_line("ready.", color="green", use_color=use_color)
    else:
        write_line("not ready.", color="red", use_color=use_color)


def _short_version(version: str) -> str:
    parts = version.split(".")
    if len(parts) >= 2:
        return ".".join(parts[:2])
    return version


def prompt_line(active_job: str = "", use_color: bool | None = None, readline_safe: bool = True) -> str:
    """Return the interactive shell prompt."""
    if use_color is None:
        use_color = sys.stdout.isatty()
    if active_job:
        return (
            colorize("bl", "green", enabled=use_color, readline_safe=readline_safe)
            + colorize(" [", "white", enabled=use_color, readline_safe=readline_safe)
            + colorize(f"#{active_job}", "cyan", enabled=use_color, readline_safe=readline_safe)
            + colorize("] ❯ ", "yellow", enabled=use_color, readline_safe=readline_safe)
        )
    return (
        colorize("blackline", "green", enabled=use_color, readline_safe=readline_safe)
        + colorize(" ❯ ", "yellow", enabled=use_color, readline_safe=readline_safe)
    )
