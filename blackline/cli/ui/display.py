"""Terminal display helpers."""

from __future__ import annotations

import sys

from blackline.cli.ui.colors import colorize

Segment = tuple[str, str]


def write_line(text: str = "", *, color: str = "white", bold: bool = False, use_color: bool | None = None) -> None:
    """Write one styled line to stdout."""
    if use_color is None:
        use_color = sys.stdout.isatty()
    print(colorize(text, color, bold=bold, enabled=use_color))


def write_segments(segments: list[Segment], *, use_color: bool | None = None) -> None:
    """Write one line made from individually styled segments."""
    if use_color is None:
        use_color = sys.stdout.isatty()
    print("".join(colorize(text, color, enabled=use_color) for text, color in segments))


def tagged(kind: str, message: str, *, use_color: bool | None = None) -> None:
    """Write a standard tagged status line."""
    colors = {
        "info": "cyan",
        "warn": "yellow",
        "error": "red",
        "result": "green",
    }
    write_segments(
        [
            (f"[{kind}]", colors.get(kind, "white")),
            (f" {message}", "white"),
        ],
        use_color=use_color,
    )


def info(message: str, *, use_color: bool | None = None) -> None:
    tagged("info", message, use_color=use_color)


def warn(message: str, *, use_color: bool | None = None) -> None:
    tagged("warn", message, use_color=use_color)


def error(message: str, *, use_color: bool | None = None) -> None:
    tagged("error", message, use_color=use_color)


def result(message: str, *, use_color: bool | None = None) -> None:
    tagged("result", message, use_color=use_color)


def section(title: str, rows: list[tuple[str, str]], *, use_color: bool | None = None) -> None:
    """Render a simple section with aligned key/value rows."""
    write_line(f"[{title}]", use_color=use_color)
    if not rows:
        return

    width = max(len(key) for key, _ in rows)
    for key, value in rows:
        write_segments(
            [
                (key.ljust(width), "muted"),
                (" : ", "muted"),
                (value, "white"),
            ],
            use_color=use_color,
        )


def job_id(identifier: str, *, use_color: bool | None = None) -> None:
    """Render a job identifier in the shared job-system style."""
    write_segments([(identifier, "cyan")], use_color=use_color)
