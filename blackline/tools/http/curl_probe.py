"""Curl probe tool."""

from __future__ import annotations

from typing import Callable

from blackline.tools.external import resolve_external_binary
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
    binary, message = resolve_external_binary("curl", "curl", executor)
    if not binary:
        return {"url": url, "ok": False, "error": message}

    command = [binary, "-k", "-L", "-i", "-sS", "--max-time", str(int(timeout)), url]
    if host_header:
        command.extend(["-H", f"Host: {host_header}"])
    runner = executor or (lambda args: run_command(args, timeout=timeout + 1.0))
    result = runner(tuple(command))
    return parse_curl_probe_output(url, result.stdout, stderr=result.stderr, returncode=result.returncode)
