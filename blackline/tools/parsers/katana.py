"""Parse ProjectDiscovery Katana JSONL crawl output."""

from __future__ import annotations

import json


def parse_katana_jsonl(stdout: str) -> list[dict[str, object]]:
    """Return unique, normalized page observations from Katana JSONL output."""
    findings: list[dict[str, object]] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, dict):
            continue
        request = raw.get("request", {})
        response = raw.get("response", {})
        request = request if isinstance(request, dict) else {}
        response = response if isinstance(response, dict) else {}
        url = str(request.get("endpoint") or request.get("url") or raw.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        status = response.get("status_code", raw.get("status_code"))
        technologies = response.get("technologies", raw.get("technologies", ()))
        if not isinstance(technologies, list):
            technologies = ()
        findings.append(
            {
                "url": url,
                "method": str(request.get("method") or raw.get("method") or "GET").upper(),
                "status_code": int(status) if isinstance(status, int) or str(status).isdigit() else None,
                "title": str(response.get("title") or raw.get("title") or ""),
                "technologies": tuple(str(item) for item in technologies if str(item).strip()),
            }
        )
    return findings
