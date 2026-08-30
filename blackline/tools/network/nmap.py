"""Nmap tool."""

from __future__ import annotations

from dataclasses import dataclass
import os
from shutil import which
from typing import Callable

from blackline.config.tool_loader import get_tool_config
from blackline.tools.parsers.nmap import NmapParsedResult, parse_nmap_output
from blackline.utils.exec import CommandResult, run_command


@dataclass(frozen=True, slots=True)
class NmapRequest:
    """Normalized nmap execution request."""

    target: str
    ports: str = ""
    top_ports: str = ""
    profile: str = "default"
    timing: str = ""
    service_detection: bool = False
    scripts: bool = False
    os_detection: bool = False
    extra_flags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class NmapExecution:
    """Outcome of an nmap execution attempt."""

    ok: bool
    command: tuple[str, ...]
    parsed: NmapParsedResult
    elapsed_seconds: float = 0.0
    error: str = ""
    stderr: str = ""
    used_sudo: bool = False


def build_nmap_command(request: NmapRequest, *, config: dict | None = None) -> tuple[str, ...]:
    """Build the nmap command for a normalized request."""
    config = config or get_tool_config("nmap")
    defaults = _mapping(config.get("defaults"))
    profile_name = request.profile or str(defaults.get("profile") or "default")
    profiles = _mapping(config.get("profiles"))
    profile = _mapping(profiles.get(profile_name))
    binary = str(config.get("binary") or "nmap")

    command = [binary]
    command.extend(_string_list(profile.get("flags")))

    timing = request.timing
    if timing:
        _replace_or_append_flag(command, "-T", f"-{timing}")
    elif not any(item.startswith("-T") for item in command):
        default_timing = str(defaults.get("timing") or "")
        if default_timing:
            command.append(f"-{default_timing}")

    ports = request.ports or str(defaults.get("ports") or "")
    if request.top_ports:
        command.extend(["--top-ports", request.top_ports])
    elif ports:
        command.extend(["-p", ports])

    options = _mapping(config.get("options"))
    if request.service_detection:
        command.extend(_option_flags(options, "service_detection"))
    if request.scripts:
        command.extend(_option_flags(options, "scripts"))
    if request.os_detection:
        command.extend(_option_flags(options, "os_detection"))
    if request.extra_flags:
        command.extend(request.extra_flags)

    command.append(request.target)
    return tuple(_dedupe_flags(command))


def requires_sudo_for_request(request: NmapRequest, *, config: dict | None = None) -> bool:
    """Return True when the request needs elevated privileges."""
    config = config or get_tool_config("nmap")
    command = build_nmap_command(request, config=config)
    return _requires_sudo(command, config=config)


def execute_nmap(
    request: NmapRequest,
    *,
    executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    config: dict | None = None,
    timeout_seconds: float | None = None,
) -> NmapExecution:
    """Execute nmap and parse the resulting stdout."""
    config = config or get_tool_config("nmap")
    defaults = _mapping(config.get("defaults"))
    timeout_seconds = timeout_seconds if timeout_seconds is not None else _optional_timeout(defaults.get("timeout_seconds"))
    command = build_nmap_command(request, config=config)
    execution_command, used_sudo = _execution_command(command, config=config)
    if executor is None and _missing_required_binary(execution_command):
        return NmapExecution(
            ok=False,
            command=execution_command,
            parsed=NmapParsedResult(target=request.target),
            elapsed_seconds=0.0,
            error=_missing_binary_message(execution_command),
            used_sudo=used_sudo,
        )

    executor = executor or (lambda args: run_command(args, timeout=timeout_seconds))
    result = executor(execution_command)
    parsed = parse_nmap_output(result.stdout)
    stderr = _clean_message(result.stderr)
    return NmapExecution(
        ok=result.ok,
        command=execution_command,
        parsed=parsed,
        elapsed_seconds=result.elapsed_seconds,
        error=_build_error_message(result, stderr=stderr, timeout_seconds=timeout_seconds),
        stderr=stderr,
        used_sudo=used_sudo,
    )


def _mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _option_flags(options: dict, name: str) -> list[str]:
    return _string_list(_mapping(options.get(name)).get("flags"))


def _replace_or_append_flag(command: list[str], prefix: str, value: str) -> None:
    for index, item in enumerate(command):
        if item.startswith(prefix):
            command[index] = value
            return
    command.append(value)


def _dedupe_flags(command: list[str]) -> list[str]:
    deduped: list[str] = []
    for item in command:
        if item in {"-Pn", "-sV", "-sC", "-O", "-A"} and item in deduped:
            continue
        deduped.append(item)
    return deduped


def _build_error_message(result: CommandResult, *, stderr: str, timeout_seconds: float | None) -> str:
    if result.ok:
        return ""
    if result.returncode == 124:
        if stderr:
            return stderr
        if timeout_seconds is not None:
            return f"nmap scan timed out after {timeout_seconds:.1f} seconds"
        return "nmap scan timed out"
    if _sudo_authentication_required(stderr):
        return "sudo authentication required for this scan; run 'sudo -v' and retry"
    if _sudo_access_denied(stderr):
        return "sudo access denied for this scan"
    if stderr:
        return f"nmap scan failed: {stderr}"
    return f"nmap scan failed (exit code {result.returncode})"


def _clean_message(message: str) -> str:
    return " ".join(str(message).split())


def _optional_timeout(value: object) -> float | None:
    try:
        if value in {None, "", 0, "0"}:
            return None
        timeout = float(value)
    except (TypeError, ValueError):
        return None
    return timeout if timeout > 0 else None


def display_command(command: tuple[str, ...]) -> tuple[str, ...]:
    """Return a user-facing command line without helper-only sudo flags."""
    if len(command) >= 2 and command[0] == "sudo" and command[1] == "-n":
        return ("sudo", *command[2:])
    return command


def _execution_command(command: tuple[str, ...], *, config: dict) -> tuple[tuple[str, ...], bool]:
    if not _requires_sudo(command, config=config):
        return command, False

    sudo_config = _mapping(config.get("sudo"))
    non_interactive = bool(sudo_config.get("non_interactive", True))
    sudo_command = ["sudo"]
    if non_interactive:
        sudo_command.append("-n")
    sudo_command.extend(command)
    return tuple(sudo_command), True


def _requires_sudo(command: tuple[str, ...], *, config: dict) -> bool:
    if _is_root():
        return False

    sudo_config = _mapping(config.get("sudo"))
    if not bool(sudo_config.get("enabled", False)):
        return False

    privileged_flags = _string_list(sudo_config.get("privileged_flags"))
    return any(flag in command for flag in privileged_flags)


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    try:
        return bool(geteuid() == 0)
    except OSError:
        return False


def _missing_required_binary(command: tuple[str, ...]) -> bool:
    if not command:
        return True

    binary = command[0]
    if which(binary) is None:
        return True

    if binary == "sudo":
        wrapped_binary = _wrapped_binary(command)
        if not wrapped_binary or which(wrapped_binary) is None:
            return True
    return False


def _missing_binary_message(command: tuple[str, ...]) -> str:
    if not command:
        return "nmap binary not found"
    if command[0] != "sudo":
        return "nmap binary not found"
    if which("sudo") is None:
        return "sudo binary not found"
    return "nmap binary not found"


def _wrapped_binary(command: tuple[str, ...]) -> str:
    if not command:
        return ""
    if command[0] != "sudo":
        return command[0]
    if len(command) >= 3 and command[1] == "-n":
        return command[2]
    if len(command) >= 2:
        return command[1]
    return ""


def _sudo_authentication_required(stderr: str) -> bool:
    lowered = stderr.lower()
    return "a password is required" in lowered or "password is required" in lowered


def _sudo_access_denied(stderr: str) -> bool:
    lowered = stderr.lower()
    return "not in the sudoers" in lowered or "permission denied" in lowered
