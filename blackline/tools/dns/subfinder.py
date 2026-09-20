"""ProjectDiscovery Subfinder adapter for passive subdomain enumeration."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Callable

from blackline.config.tool_loader import get_tool_config
from blackline.tools.external import configured_flags, resolve_external_binary
from blackline.tools.parsers.subfinder import parse_subfinder_jsonl
from blackline.utils.exec import CommandResult, run_command


@dataclass(frozen=True, slots=True)
class SubdomainFinding:
    host: str
    sources: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SubfinderResult:
    ok: bool
    domain: str
    subdomains: tuple[SubdomainFinding, ...] = ()
    error: str = ""
    skipped: bool = False
    negative_observation: bool = False
    raw_output: str = ""
    elapsed_seconds: float = 0.0


def enumerate_subdomains(
    domain: str,
    *,
    timeout_seconds: float = 60.0,
    executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    config: dict | None = None,
) -> SubfinderResult:
    """Passively enumerate in-scope subdomains using Subfinder JSONL output."""
    domain = domain.strip().lower().rstrip(".")
    config = config or get_tool_config("subfinder")
    binary = str(config.get("binary") or "subfinder")
    if not domain:
        return SubfinderResult(False, domain, error="missing subfinder domain")
    binary, message = resolve_external_binary("subfinder", binary, executor)
    if not binary:
        return SubfinderResult(False, domain, skipped=True, error=message)
    command = build_subfinder_command(domain, binary=binary, config=config)
    started = time.perf_counter()
    runner = executor or (lambda args: run_command(args, timeout=timeout_seconds))
    execution = runner(command)
    findings = tuple(SubdomainFinding(**item) for item in parse_subfinder_jsonl(execution.stdout, domain=domain))
    elapsed = execution.elapsed_seconds or (time.perf_counter() - started)
    if findings:
        return SubfinderResult(True, domain, subdomains=findings, raw_output=execution.stdout, elapsed_seconds=elapsed)
    if execution.returncode == 0:
        return SubfinderResult(True, domain, negative_observation=True, raw_output=execution.stdout, elapsed_seconds=elapsed)
    return SubfinderResult(False, domain, error=execution.stderr.strip() or "subfinder enumeration failed", raw_output=execution.stdout, elapsed_seconds=elapsed)


def build_subfinder_command(domain: str, *, binary: str = "subfinder", config: dict | None = None) -> tuple[str, ...]:
    """Build a quiet passive Subfinder command with JSONL source attribution."""
    config = config or get_tool_config("subfinder")
    return (binary, "-d", domain, *configured_flags(config))
