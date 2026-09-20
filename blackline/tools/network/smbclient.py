"""Bounded anonymous SMB share enumeration with smbclient."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Callable

from blackline.config.tool_loader import get_tool_config
from blackline.tools.external import configured_flags, resolve_external_binary
from blackline.tools.parsers.smbclient import parse_smbclient_grepable
from blackline.utils.exec import CommandResult, run_command


@dataclass(frozen=True, slots=True)
class SmbShare:
    """One share advertised through an anonymous SMB listing."""

    name: str
    type: str
    comment: str = ""


@dataclass(frozen=True, slots=True)
class SmbClientResult:
    """Result of a read-only anonymous SMB share enumeration."""

    ok: bool
    target: str
    port: int
    shares: tuple[SmbShare, ...] = ()
    error: str = ""
    skipped: bool = False
    negative_observation: bool = False
    warnings: tuple[str, ...] = ()
    raw_output: str = ""
    elapsed_seconds: float = 0.0


def enumerate_smb_shares(
    target: str,
    *,
    port: int = 445,
    timeout_seconds: float = 15.0,
    executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    config: dict | None = None,
) -> SmbClientResult:
    """List publicly enumerable shares without credentials or share access."""
    target = target.strip()
    config = config or get_tool_config("smbclient")
    binary = str(config.get("binary") or "smbclient")
    if not target:
        return SmbClientResult(False, target, port, error="missing SMB target")
    if not 1 <= port <= 65535:
        return SmbClientResult(False, target, port, error="invalid SMB port")
    binary, message = resolve_external_binary("smbclient", binary, executor)
    if not binary:
        return SmbClientResult(False, target, port, skipped=True, error=message)
    command = build_smbclient_command(target, port=port, binary=binary, config=config)
    started = time.perf_counter()
    runner = executor or (lambda args: run_command(args, timeout=timeout_seconds))
    execution = runner(command)
    elapsed = execution.elapsed_seconds or (time.perf_counter() - started)
    shares = tuple(SmbShare(**share) for share in parse_smbclient_grepable(execution.stdout))
    if execution.returncode == 0:
        return SmbClientResult(True, target, port, shares=shares, negative_observation=not shares, raw_output=execution.stdout, elapsed_seconds=elapsed)
    detail = execution.stderr.strip() or execution.stdout.strip() or "smbclient query failed"
    if "ACCESS_DENIED" in detail.upper() or "LOGON_FAILURE" in detail.upper():
        return SmbClientResult(
            True,
            target,
            port,
            warnings=("anonymous SMB share listing was denied",),
            raw_output=execution.stdout,
            elapsed_seconds=elapsed,
        )
    return SmbClientResult(False, target, port, error=detail, raw_output=execution.stdout, elapsed_seconds=elapsed)


def build_smbclient_command(
    target: str,
    *,
    port: int = 445,
    binary: str = "smbclient",
    config: dict | None = None,
) -> tuple[str, ...]:
    """Build an anonymous, grepable SMB listing command."""
    config = config or get_tool_config("smbclient")
    return (binary, "-L", f"//{target}", "-p", str(port), *configured_flags(config, default=("-N", "-g")))
