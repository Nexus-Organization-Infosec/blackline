"""ProjectDiscovery Katana adapter for bounded web crawling."""

from __future__ import annotations

from dataclasses import dataclass
from shutil import which
import time
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from blackline.config.tool_loader import get_tool_config
from blackline.tools.parsers.katana import parse_katana_jsonl
from blackline.utils.exec import CommandResult, run_command


@dataclass(frozen=True, slots=True)
class KatanaFinding:
    """One crawled web endpoint with compact response metadata."""

    url: str
    method: str = "GET"
    status_code: int | None = None
    title: str = ""
    technologies: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class KatanaResult:
    """Outcome of a Katana crawl; no endpoints is a negative observation."""

    ok: bool
    target: str
    crawl_url: str = ""
    findings: tuple[KatanaFinding, ...] = ()
    error: str = ""
    skipped: bool = False
    negative_observation: bool = False
    raw_output: str = ""
    elapsed_seconds: float = 0.0


def crawl_with_katana(
    target: str,
    *,
    host: str = "",
    scheme: str = "",
    path: str = "",
    port: str = "",
    timeout_seconds: float = 30.0,
    executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    config: dict | None = None,
) -> KatanaResult:
    """Crawl one explicit web target using bounded, JSONL Katana output."""
    config = config or get_tool_config("katana")
    binary = str(config.get("binary") or "katana")
    if executor is None and which(binary) is None:
        return KatanaResult(False, target, skipped=True, error="katana unavailable")
    crawl_url = build_katana_target(target, host=host, scheme=scheme, path=path, port=port)
    if not crawl_url:
        return KatanaResult(False, target, error="missing Katana target")
    started = time.perf_counter()
    command = build_katana_command(crawl_url, binary=binary, config=config)
    runner = executor or (lambda args: run_command(args, timeout=timeout_seconds))
    execution = runner(command)
    findings = tuple(KatanaFinding(**item) for item in parse_katana_jsonl(execution.stdout))
    elapsed = execution.elapsed_seconds or (time.perf_counter() - started)
    if findings:
        return KatanaResult(True, target, crawl_url, findings, raw_output=execution.stdout, elapsed_seconds=elapsed)
    if execution.returncode == 0:
        return KatanaResult(True, target, crawl_url, negative_observation=True, raw_output=execution.stdout, elapsed_seconds=elapsed)
    return KatanaResult(False, target, crawl_url, error=execution.stderr.strip() or "Katana crawl failed", raw_output=execution.stdout, elapsed_seconds=elapsed)


def build_katana_target(target: str, *, host: str = "", scheme: str = "", path: str = "", port: str = "") -> str:
    """Produce Katana's required URL input while preserving explicit URL paths."""
    value = target.strip()
    parsed = urlsplit(value)
    if parsed.scheme and parsed.netloc:
        return value
    resolved_host = host.strip() or value
    if not resolved_host:
        return ""
    netloc = resolved_host
    if port.strip() and ":" not in resolved_host:
        netloc = f"{resolved_host}:{port.strip()}"
    return urlunsplit((scheme.strip() or "https", netloc, path.strip() or "/", "", ""))


def build_katana_command(crawl_url: str, *, binary: str = "katana", config: dict | None = None) -> tuple[str, ...]:
    """Build a bounded JSONL crawl invocation from tool configuration."""
    config = config or get_tool_config("katana")
    flags = config.get("flags", [])
    flags = [str(flag) for flag in flags] if isinstance(flags, list) else []
    return tuple([binary, "-u", crawl_url, *flags])
