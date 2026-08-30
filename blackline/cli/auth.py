"""Shell-owned privilege escalation helpers."""

from __future__ import annotations

import getpass
import os
import time

from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.cli.ui.display import write_line, write_segments
from blackline.config.tool_loader import get_tool_config
from blackline.utils.exec import run_command


def refresh_sudo_state(state: ShellState) -> None:
    """Keep the shell privilege state aligned with the cached sudo session."""
    if _is_root():
        state.sudo_authenticated = True
        state.sudo_expires_at = float("inf")
        return

    if state.sudo_authenticated and state.sudo_expires_at:
        if time.monotonic() >= state.sudo_expires_at:
            state.sudo_authenticated = False
            state.sudo_expires_at = 0.0


def is_elevated(state: ShellState) -> bool:
    """Return True when the shell should render as elevated."""
    refresh_sudo_state(state)
    return state.sudo_authenticated


def ensure_elevated_session(state: ShellState, *, use_color: bool | None = None) -> bool:
    """Prompt for sudo once and keep the shell in an elevated state."""
    refresh_sudo_state(state)
    if state.sudo_authenticated:
        return True

    _write_auth("elevated privileges required", use_color=use_color)

    while True:
        password = _prompt_password(state)
        if password is None:
            _write_auth_failed("authentication cancelled", use_color=use_color)
            return False

        try:
            _write_auth("validating...", use_color=use_color)
            outcome = run_command(
                ("sudo", "-S", "-p", "", "-v"),
                timeout=30.0,
                input_text=f"{password}\n",
            )
        finally:
            password = ""

        if outcome.ok:
            state.sudo_authenticated = True
            state.sudo_expires_at = time.monotonic() + _sudo_session_seconds()
            _write_auth("session authenticated", use_color=use_color)
            return True

        normalized = _normalize_auth_error(outcome.stderr)
        _write_auth_failed(normalized, use_color=use_color)
        if normalized != "incorrect password":
            return False


def close_elevated_session(state: ShellState, *, use_color: bool | None = None) -> bool:
    """Close the current elevated shell state."""
    if not is_elevated(state):
        return False

    if not _is_root():
        run_command(("sudo", "-k"), timeout=10.0)

    state.sudo_authenticated = False
    state.sudo_expires_at = 0.0
    _write_auth("elevated session closed", use_color=use_color)
    return True


def _prompt_password(state: ShellState) -> str | None:
    session = state.prompt_session
    if session is not None:
        try:
            from prompt_toolkit.layout.processors import PasswordProcessor

            return str(
                session.prompt(
                    [
                        ("class:auth.tag", "[sudo]"),
                        ("class:auth.label", " password: "),
                    ],
                    is_password=True,
                    input_processors=[PasswordProcessor(char="")],
                    completer=None,
                    complete_while_typing=False,
                    lexer=None,
                )
            )
        except KeyboardInterrupt:
            print()
            return None
        except EOFError:
            print()
            return None

    try:
        return getpass.getpass("[sudo] password: ")
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def _normalize_auth_error(stderr: str) -> str:
    lowered = " ".join(stderr.split()).lower()
    if not lowered:
        return "authentication failed"
    if "try again" in lowered or "incorrect password" in lowered:
        return "incorrect password"
    if "no password was provided" in lowered:
        return "incorrect password"
    if "not in the sudoers" in lowered or "permission denied" in lowered:
        return "access denied"
    if "sudo binary not found" in lowered or "no such file or directory" in lowered:
        return "sudo unavailable"
    return "authentication failed"


def _write_auth(message: str, *, use_color: bool | None = None) -> None:
    write_segments([("[auth]", "cyan"), (f" {message}", "white")], use_color=use_color)


def _write_auth_failed(message: str, *, use_color: bool | None = None) -> None:
    write_line("[auth failed]", color="red", use_color=use_color)
    write_line(message, use_color=use_color)


def _sudo_session_seconds() -> float:
    config = get_tool_config("nmap")
    sudo = config.get("sudo", {}) if isinstance(config, dict) else {}
    if isinstance(sudo, dict):
        value = sudo.get("session_seconds", 300)
        try:
            seconds = float(value)
        except (TypeError, ValueError):
            return 300.0
        if seconds > 0:
            return seconds
    return 300.0


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    try:
        return bool(geteuid() == 0)
    except OSError:
        return False
