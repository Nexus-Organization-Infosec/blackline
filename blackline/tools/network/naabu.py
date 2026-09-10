"""ProjectDiscovery Naabu adapter for fast TCP port discovery."""

from __future__ import annotations

from dataclasses import dataclass
from shutil import which
import time
from typing import Callable

from blackline.config.tool_loader import get_tool_config
from blackline.tools.parsers.naabu import parse_naabu_jsonl
from blackline.utils.exec import CommandResult, run_command


@dataclass(frozen=True, slots=True)
class NaabuPort:
    host: str
    port: int
    protocol: str = "tcp"


@dataclass(frozen=True, slots=True)
class NaabuResult:
    ok: bool
    target: str
    ports: tuple[NaabuPort, ...] = ()
    error: str = ""
    skipped: bool = False
    negative_observation: bool = False
    raw_output: str = ""
    elapsed_seconds: float = 0.0


def scan_ports_with_naabu(
    target: str,
    *,
    ports: str = "",
    top_ports: str = "",
    timeout_seconds: float = 60.0,
    executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    config: dict | None = None,
) -> NaabuResult:
    """Run Naabu's connect scan and return compact open TCP port evidence."""
    config = config or get_tool_config("naabu")
    binary = str(config.get("binary") or "naabu")
    target = target.strip()
    if not target:
        return NaabuResult(False, target, error="missing Naabu target")
    if executor is None and which(binary) is None:
        return NaabuResult(False, target, skipped=True, error="naabu unavailable")
    started = time.perf_counter()
    command = build_naabu_command(target, ports=ports, top_ports=top_ports, binary=binary, config=config)
    runner = executor or (lambda args: run_command(args, timeout=timeout_seconds))
    execution = runner(command)
    discovered = tuple(NaabuPort(**item) for item in parse_naabu_jsonl(execution.stdout))
    elapsed = execution.elapsed_seconds or (time.perf_counter() - started)
    if execution.returncode == 0:
        return NaabuResult(True, target, discovered, negative_observation=not discovered, raw_output=execution.stdout, elapsed_seconds=elapsed)
    return NaabuResult(False, target, error=execution.stderr.strip() or "Naabu scan failed", raw_output=execution.stdout, elapsed_seconds=elapsed)


def build_naabu_command(target: str, *, ports: str = "", top_ports: str = "", binary: str = "naabu", config: dict | None = None) -> tuple[str, ...]:
    """Build Naabu JSONL discovery while preserving explicit port constraints."""
    config = config or get_tool_config("naabu")
    flags = config.get("flags", [])
    flags = [str(flag) for flag in flags] if isinstance(flags, list) else []
    command = [binary, "-host", target]
    if ports.strip():
        command.extend(["-p", "-" if ports.strip() == "all" else ports.strip()])
    elif top_ports.strip() in {"100", "1000", "full"}:
        command.extend(["-top-ports", top_ports.strip()])
    elif top_ports.strip():
        # Naabu has only built-in 100/1000/full lists. A full connect scan keeps
        # Blackline's broader Nmap policy from silently losing coverage.
        command.extend(["-p", "-"])
    command.extend(flags)
    return tuple(command)
