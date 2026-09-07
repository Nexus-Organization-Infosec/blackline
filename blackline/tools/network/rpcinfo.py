"""Structured adapter for rpcbind/portmapper enumeration with rpcinfo."""

from __future__ import annotations

from dataclasses import dataclass
from shutil import which
import time
from typing import Callable

from blackline.config.tool_loader import get_tool_config
from blackline.tools.parsers.rpcinfo import parse_rpcinfo_table
from blackline.utils.exec import CommandResult, run_command


@dataclass(frozen=True, slots=True)
class RpcRegistration:
    """One RPC program mapping reported by the target's portmapper."""

    program: int
    version: int
    protocol: str
    port: int
    service: str = ""


@dataclass(frozen=True, slots=True)
class RpcInfoResult:
    """Outcome of a bounded portmapper registry query."""

    ok: bool
    target: str
    registrations: tuple[RpcRegistration, ...] = ()
    error: str = ""
    skipped: bool = False
    negative_observation: bool = False
    raw_output: str = ""
    elapsed_seconds: float = 0.0


def query_rpcinfo(
    target: str,
    *,
    timeout_seconds: float = 12.0,
    executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    config: dict | None = None,
) -> RpcInfoResult:
    """List registered RPC programs on one target with ``rpcinfo -p``."""
    target = target.strip()
    config = config or get_tool_config("rpcinfo")
    binary = str(config.get("binary") or "rpcinfo")
    if not target:
        return RpcInfoResult(False, target, error="missing rpcinfo target")
    if executor is None and which(binary) is None:
        return RpcInfoResult(False, target, skipped=True, error="rpcinfo unavailable")
    command = build_rpcinfo_command(target, binary=binary, config=config)
    started = time.perf_counter()
    runner = executor or (lambda args: run_command(args, timeout=timeout_seconds))
    execution = runner(command)
    elapsed = execution.elapsed_seconds or (time.perf_counter() - started)
    records = tuple(RpcRegistration(**record) for record in parse_rpcinfo_table(execution.stdout))
    if records:
        return RpcInfoResult(True, target, registrations=records, raw_output=execution.stdout, elapsed_seconds=elapsed)
    if execution.returncode == 0:
        return RpcInfoResult(True, target, negative_observation=True, raw_output=execution.stdout, elapsed_seconds=elapsed)
    return RpcInfoResult(False, target, error=execution.stderr.strip() or "rpcinfo query failed", raw_output=execution.stdout, elapsed_seconds=elapsed)


def build_rpcinfo_command(target: str, *, binary: str = "rpcinfo", config: dict | None = None) -> tuple[str, ...]:
    """Build the portable registered-program listing invocation."""
    config = config or get_tool_config("rpcinfo")
    flags = config.get("flags", ["-p"])
    flags = [str(flag) for flag in flags] if isinstance(flags, list) else ["-p"]
    return tuple([binary, *flags, target])
