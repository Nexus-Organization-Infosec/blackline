"""WhatWeb adapter for independent web-technology fingerprinting."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from shutil import which
from tempfile import NamedTemporaryFile
import time
from typing import Callable

from blackline.config.tool_loader import get_tool_config
from blackline.tools.http.client import build_http_probe_urls
from blackline.tools.parsers.whatweb import parse_whatweb_json
from blackline.utils.exec import CommandResult, run_command


@dataclass(frozen=True, slots=True)
class WhatWebFinding:
    """One normalized WhatWeb identification."""

    url: str
    status_code: int | None = None
    title: str = ""
    webserver: str = ""
    technologies: tuple[str, ...] = ()
    plugins: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class WhatWebResult:
    """Outcome of a WhatWeb run, including absent-tool and negative states."""

    ok: bool
    target: str
    findings: tuple[WhatWebFinding, ...] = ()
    error: str = ""
    skipped: bool = False
    negative_observation: bool = False
    raw_output: str = ""
    elapsed_seconds: float = 0.0


def fingerprint_with_whatweb(
    target: str,
    *,
    mode: str,
    host: str = "",
    scheme: str = "",
    path: str = "",
    port: str = "",
    timeout_seconds: float = 20.0,
    executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    config: dict | None = None,
) -> WhatWebResult:
    """Run a low-aggression WhatWeb scan and retain its JSON evidence."""
    config = config or get_tool_config("whatweb")
    binary = str(config.get("binary") or "whatweb")
    if executor is None and which(binary) is None:
        return WhatWebResult(False, target, skipped=True, error="whatweb unavailable")
    urls = build_http_probe_urls(mode=mode, host=(host or target).strip(), scheme=scheme, path=path, port=port)
    if not urls:
        return WhatWebResult(False, target, error="missing WhatWeb target")

    with NamedTemporaryFile(prefix="blackline-whatweb-", suffix=".json", delete=False) as handle:
        log_path = Path(handle.name)
    started = time.perf_counter()
    try:
        command = build_whatweb_command(urls, log_path=log_path, binary=binary, config=config)
        runner = executor or (lambda args: run_command(args, timeout=timeout_seconds))
        execution = runner(command)
        try:
            json_output = log_path.read_text(encoding="utf-8")
        except OSError:
            json_output = ""
    finally:
        log_path.unlink(missing_ok=True)
    elapsed = execution.elapsed_seconds or (time.perf_counter() - started)
    parsed = parse_whatweb_json(json_output)
    findings = tuple(
        WhatWebFinding(
            url=str(item["url"]),
            status_code=item["status_code"] if isinstance(item["status_code"], int) else None,
            title=str(item["title"]),
            webserver=str(item["webserver"]),
            technologies=tuple(item["technologies"]),
            plugins=tuple(item["plugins"]),
        )
        for item in parsed
    )
    raw_output = json_output or execution.stdout
    if findings:
        return WhatWebResult(True, target, findings=findings, raw_output=raw_output, elapsed_seconds=elapsed)
    if execution.returncode == 0:
        return WhatWebResult(True, target, negative_observation=True, raw_output=raw_output, elapsed_seconds=elapsed)
    return WhatWebResult(False, target, error=execution.stderr.strip() or "WhatWeb fingerprint failed", raw_output=raw_output, elapsed_seconds=elapsed)


def build_whatweb_command(
    urls: list[str],
    *,
    log_path: Path,
    binary: str = "whatweb",
    config: dict | None = None,
) -> tuple[str, ...]:
    """Build a low-noise WhatWeb request that logs structured results."""
    config = config or get_tool_config("whatweb")
    flags = config.get("flags", [])
    flags = [str(flag) for flag in flags] if isinstance(flags, list) else []
    return tuple([binary, *flags, f"--log-json={log_path}", *urls])
