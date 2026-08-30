"""Parse curl probe output."""

from __future__ import annotations

import re

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def parse_curl_probe_output(
    url: str,
    stdout: str,
    *,
    stderr: str = "",
    returncode: int = 0,
) -> dict[str, object]:
    """Parse a fallback curl probe response into a structured finding mapping."""
    text = stdout or ""
    blocks = [block for block in text.split("\r\n\r\n") if block.strip()]
    header_lines: list[str] = []
    body = text

    if blocks:
        last_header_block = None
        for block in blocks:
            if block.startswith("HTTP/"):
                last_header_block = block
        if last_header_block is not None:
            header_lines = [line for line in last_header_block.splitlines() if line.strip()]
            index = text.rfind(last_header_block)
            body = text[index + len(last_header_block) :].lstrip("\r\n")

    status_code = None
    headers: dict[str, str] = {}
    redirect_to = ""
    if header_lines:
        first = header_lines[0].split()
        if len(first) >= 2 and first[1].isdigit():
            status_code = int(first[1])
        for line in header_lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        redirect_to = headers.get("location", "")

    ok = returncode == 0 and status_code is not None and status_code < 400
    error = stderr.strip() if stderr.strip() else ("" if ok else "http probe failed")
    return {
        "url": url,
        "status_code": status_code,
        "title": _extract_title(body),
        "redirect_to": redirect_to,
        "headers": headers,
        "ok": ok,
        "error": error,
    }


def _extract_title(body: str) -> str:
    match = _TITLE_RE.search(body or "")
    if not match:
        return ""
    return " ".join(match.group(1).split()).strip()
