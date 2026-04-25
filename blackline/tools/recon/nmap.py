"""Nmap tool."""

from __future__ import annotations

from dataclasses import dataclass
from shutil import which
from typing import Callable

from blackline.config.tool_loader import get_tool_config
from blackline.tools.recon.parsers.nmap_parser import NmapParsedResult, parse_nmap_output
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


def execute_nmap(
    request: NmapRequest,
    *,
    executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    config: dict | None = None,
) -> NmapExecution:
    """Execute nmap and parse the resulting stdout."""
    config = config or get_tool_config("nmap")
    defaults = _mapping(config.get("defaults"))
    timeout_seconds = _optional_timeout(defaults.get("timeout_seconds"))
    command = build_nmap_command(request, config=config)
    if which(command[0]) is None and executor is None:
        return NmapExecution(
            ok=False,
            command=command,
            parsed=NmapParsedResult(target=request.target),
            elapsed_seconds=0.0,
            error="nmap binary not found",
        )

    executor = executor or (lambda args: run_command(args, timeout=timeout_seconds))
    result = executor(command)
    parsed = parse_nmap_output(result.stdout)
    stderr = _clean_message(result.stderr)
    return NmapExecution(
        ok=result.ok,
        command=command,
        parsed=parsed,
        elapsed_seconds=result.elapsed_seconds,
        error=_build_error_message(result, stderr=stderr, timeout_seconds=timeout_seconds),
        stderr=stderr,
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
