"""Parse ProjectDiscovery httpx JSONL output."""

from __future__ import annotations

import json


def parse_httpx_jsonl(stdout: str) -> list[dict[str, object]]:
    """Return normalized findings from valid JSON lines, ignoring noise safely."""
    findings: list[dict[str, object]] = []
    for line in (stdout or "").splitlines():
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, dict):
            continue
        status = raw.get("status_code")
        technologies = raw.get("technologies", raw.get("tech", ()))
        if not isinstance(technologies, list):
            technologies = ()
        tls = raw.get("tls", {})
        findings.append(
            {
                "url": str(raw.get("url", "")),
                "status_code": int(status) if isinstance(status, int) or str(status).isdigit() else None,
                "title": str(raw.get("title", "")),
                "redirect_to": str(raw.get("location", raw.get("final_url", ""))),
                "technologies": tuple(str(item) for item in technologies if str(item).strip()),
                "webserver": str(raw.get("webserver", raw.get("web_server", ""))),
                "tls": dict(tls) if isinstance(tls, dict) else {},
            }
        )
    return findings
