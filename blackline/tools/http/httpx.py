"""ProjectDiscovery httpx adapter for structured HTTP service confirmation."""

from __future__ import annotations

from dataclasses import dataclass, field
from shutil import which
import time
from typing import Callable

from blackline.config.tool_loader import get_tool_config
from blackline.tools.http.client import build_http_probe_urls
from blackline.tools.parsers.httpx import parse_httpx_jsonl
from blackline.utils.exec import CommandResult, run_command


@dataclass(frozen=True, slots=True)
class HttpxFinding:
    """One normalized HTTP service observation from ProjectDiscovery httpx."""

    url: str
    status_code: int | None = None
    title: str = ""
    redirect_to: str = ""
    technologies: tuple[str, ...] = ()
    webserver: str = ""
    tls: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HttpxResult:
    """Outcome of an httpx probe; absence is a negative observation, not failure."""

    ok: bool
    target: str
    findings: tuple[HttpxFinding, ...] = ()
    error: str = ""
    skipped: bool = False
    negative_observation: bool = False
    raw_output: str = ""
    elapsed_seconds: float = 0.0


def probe_httpx(
    target: str,
    *,
    mode: str,
    host: str = "",
    scheme: str = "",
    path: str = "",
    port: str = "",
    timeout_seconds: float = 10.0,
    executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    config: dict | None = None,
) -> HttpxResult:
    """Confirm HTTP services and collect compact metadata using httpx JSONL."""
    config = config or get_tool_config("httpx")
    binary = str(config.get("binary") or "httpx")
    if executor is None:
        available, message = projectdiscovery_httpx_available(binary, config=config)
        if not available:
            return HttpxResult(False, target, skipped=True, error=message)

    urls = build_http_probe_urls(mode=mode, host=(host or target).strip(), scheme=scheme, path=path, port=port)
    if not urls:
        return HttpxResult(False, target, error="missing httpx target")
    started = time.perf_counter()
    command = build_httpx_command(urls, binary=binary, config=config)
    runner = executor or (lambda args: run_command(args, timeout=timeout_seconds))
    execution = runner(command)
    parsed = parse_httpx_jsonl(execution.stdout)
    findings = tuple(
        HttpxFinding(
            url=str(item["url"]),
            status_code=item["status_code"] if isinstance(item["status_code"], int) else None,
            title=str(item["title"]),
            redirect_to=str(item["redirect_to"]),
            technologies=tuple(item["technologies"]),
            webserver=str(item["webserver"]),
            tls=dict(item["tls"]),
        )
        for item in parsed
    )
    elapsed = execution.elapsed_seconds or (time.perf_counter() - started)
    if findings:
        return HttpxResult(True, target, findings=findings, raw_output=execution.stdout, elapsed_seconds=elapsed)
    if execution.returncode == 0:
        return HttpxResult(True, target, negative_observation=True, raw_output=execution.stdout, elapsed_seconds=elapsed)
    return HttpxResult(False, target, error=execution.stderr.strip() or "httpx probe failed", raw_output=execution.stdout, elapsed_seconds=elapsed)


def discover_http_services(
    endpoints: tuple[str, ...],
    *,
    timeout_seconds: float = 10.0,
    executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    config: dict | None = None,
) -> HttpxResult:
    """Identify HTTP or HTTPS on open endpoints without guessing from ports.

    Endpoints are deliberately supplied as ``host:port`` values rather than
    URLs. httpx performs protocol discovery and its returned URL is the
    evidence for the actual scheme.
    """
    config = config or get_tool_config("httpx")
    binary = str(config.get("binary") or "httpx")
    normalized = tuple(dict.fromkeys(endpoint.strip() for endpoint in endpoints if endpoint.strip()))
    target = ", ".join(normalized)
    if executor is None:
        available, message = projectdiscovery_httpx_available(binary, config=config)
        if not available:
            return HttpxResult(False, target, skipped=True, error=message)
    if not normalized:
        return HttpxResult(True, target, negative_observation=True)

    started = time.perf_counter()
    command = build_httpx_command(list(normalized), binary=binary, config=config)
    runner = executor or (lambda args: run_command(args, timeout=timeout_seconds))
    execution = runner(command)
    parsed = parse_httpx_jsonl(execution.stdout)
    findings = tuple(
        HttpxFinding(
            url=str(item["url"]),
            status_code=item["status_code"] if isinstance(item["status_code"], int) else None,
            title=str(item["title"]),
            redirect_to=str(item["redirect_to"]),
            technologies=tuple(item["technologies"]),
            webserver=str(item["webserver"]),
            tls=dict(item["tls"]),
        )
        for item in parsed
    )
    elapsed = execution.elapsed_seconds or (time.perf_counter() - started)
    if findings:
        return HttpxResult(True, target, findings=findings, raw_output=execution.stdout, elapsed_seconds=elapsed)
    if execution.returncode == 0:
        return HttpxResult(True, target, negative_observation=True, raw_output=execution.stdout, elapsed_seconds=elapsed)
    return HttpxResult(False, target, error=execution.stderr.strip() or "httpx probe failed", raw_output=execution.stdout, elapsed_seconds=elapsed)


def build_httpx_command(urls: list[str], *, binary: str = "httpx", config: dict | None = None) -> tuple[str, ...]:
    """Build a JSONL httpx invocation without embedding tool policy in callers."""
    config = config or get_tool_config("httpx")
    flags = config.get("flags", [])
    flags = [str(flag) for flag in flags] if isinstance(flags, list) else []
    command = [binary]
    for url in urls:
        command.extend(["-u", url])
    command.extend(flags)
    return tuple(command)


def projectdiscovery_httpx_available(binary: str = "httpx", *, config: dict | None = None) -> tuple[bool, str]:
    """Verify that ``httpx`` is ProjectDiscovery's scanner, not Python's CLI.

    Both projects expose an ``httpx`` executable. The Python package accepts a
    different command line and would otherwise be mistaken for the scanner.
    """
    if which(binary) is None:
        return (False, "ProjectDiscovery httpx is unavailable; run install httpx")
    version = run_command((binary, "-version"), timeout=3.0)
    output = " ".join((version.stdout or version.stderr or "").lower().split())
    markers = _identity_markers(config)
    if version.ok and any(marker in output for marker in markers):
        return (True, "")
    return (
        False,
        "httpx on PATH is not the ProjectDiscovery scanner; install it with 'install httpx' or put the ProjectDiscovery binary first on PATH",
    )


def _identity_markers(config: dict | None) -> tuple[str, ...]:
    config = config or get_tool_config("httpx")
    configured = config.get("identity_markers", ()) if isinstance(config, dict) else ()
    markers = tuple(str(marker).strip().lower() for marker in configured if str(marker).strip()) if isinstance(configured, list) else ()
    return markers or ("current version", "httpx version", "projectdiscovery")
