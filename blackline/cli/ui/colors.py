"""Terminal color helpers."""

from __future__ import annotations

RESET = "\033[0m"
BOLD = "\033[1m"
READLINE_START = "\001"
READLINE_END = "\002"

COLORS = {
    "cyan": "\033[38;5;51m",
    "muted": "\033[38;5;245m",
    "white": "\033[38;5;252m",
    "green": "\033[38;5;82m",
    "yellow": "\033[38;5;214m",
    "red": "\033[38;5;196m",
}


def colorize(
    text: str,
    color: str = "white",
    *,
    bold: bool = False,
    enabled: bool = True,
    readline_safe: bool = False,
) -> str:
    """Apply terminal color when enabled."""
    if not enabled:
        return text

    prefix = COLORS.get(color, COLORS["white"])
    if bold:
        prefix += BOLD
    if readline_safe:
        return f"{READLINE_START}{prefix}{READLINE_END}{text}{READLINE_START}{RESET}{READLINE_END}"
    return f"{prefix}{text}{RESET}"
