"""Curl probe tool."""

from __future__ import annotations

from shutil import which
from typing import Callable

from blackline.tools.parsers.curl import parse_curl_probe_output
from blackline.utils.exec import CommandResult, run_command


def probe_with_curl(
    url: str,
    *,
    host_header: str = "",
    timeout: float = 10.0,
    executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
) -> dict[str, object]:
    """Probe one URL through curl as a fallback."""
    if which("curl") is None and executor is None:
        return {"url": url, "ok": False, "error": "curl unavailable"}

    command = ["curl", "-k", "-L", "-i", "-sS", "--max-time", str(int(timeout)), url]
    if host_header:
        command.extend(["-H", f"Host: {host_header}"])
    runner = executor or (lambda args: run_command(args, timeout=timeout + 1.0))
    result = runner(tuple(command))
    return parse_curl_probe_output(url, result.stdout, stderr=result.stderr, returncode=result.returncode)
