"""SSLyze adapter for structured TLS configuration analysis."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from shutil import which
from tempfile import NamedTemporaryFile
import time
from typing import Callable

from blackline.config.tool_loader import get_tool_config
from blackline.tools.parsers.sslyze import parse_sslyze_json
from blackline.utils.exec import CommandResult, run_command


@dataclass(frozen=True, slots=True)
class SslyzeFinding:
    host: str
    port: int | None
    protocols: tuple[str, ...] = ()
    ciphers: tuple[str, ...] = ()
    findings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SslyzeResult:
    ok: bool
    host: str
    port: int
    scans: tuple[SslyzeFinding, ...] = ()
    error: str = ""
    skipped: bool = False
    negative_observation: bool = False
    raw_output: str = ""
    elapsed_seconds: float = 0.0


def inspect_tls_configuration(
    host: str,
    *,
    port: int = 443,
    timeout_seconds: float = 45.0,
    executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    config: dict | None = None,
) -> SslyzeResult:
    """Run SSLyze against one ``host:port`` and normalize its JSON scan result."""
    host = host.strip()
    config = config or get_tool_config("sslyze")
    binary = str(config.get("binary") or "sslyze")
    if not host:
        return SslyzeResult(False, host, port, error="missing SSLyze target")
    if executor is None and which(binary) is None:
        return SslyzeResult(False, host, port, skipped=True, error="sslyze unavailable")
    with NamedTemporaryFile(prefix="blackline-sslyze-", suffix=".json", delete=False) as handle:
        json_path = Path(handle.name)
    started = time.perf_counter()
    try:
        command = build_sslyze_command(host, port=port, json_path=json_path, binary=binary, config=config)
        runner = executor or (lambda args: run_command(args, timeout=timeout_seconds))
        execution = runner(command)
        try:
            json_output = json_path.read_text(encoding="utf-8")
        except OSError:
            json_output = ""
    finally:
        json_path.unlink(missing_ok=True)
    elapsed = execution.elapsed_seconds or (time.perf_counter() - started)
    scans = tuple(SslyzeFinding(**item) for item in parse_sslyze_json(json_output))
    raw_output = json_output or execution.stdout
    if scans:
        return SslyzeResult(True, host, port, scans=scans, raw_output=raw_output, elapsed_seconds=elapsed)
    if execution.returncode == 0:
        return SslyzeResult(True, host, port, negative_observation=True, raw_output=raw_output, elapsed_seconds=elapsed)
    return SslyzeResult(False, host, port, error=execution.stderr.strip() or "SSLyze scan failed", raw_output=raw_output, elapsed_seconds=elapsed)


def build_sslyze_command(host: str, *, port: int, json_path: Path, binary: str = "sslyze", config: dict | None = None) -> tuple[str, ...]:
    """Build a quiet SSLyze scan with machine-readable output."""
    config = config or get_tool_config("sslyze")
    flags = config.get("flags", [])
    flags = [str(flag) for flag in flags] if isinstance(flags, list) else []
    return tuple([binary, *flags, f"--json_out={json_path}", f"{host}:{port}"])
