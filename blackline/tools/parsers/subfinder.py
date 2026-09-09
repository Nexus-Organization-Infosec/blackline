"""Parse ProjectDiscovery Subfinder JSONL output."""

from __future__ import annotations

import json


def parse_subfinder_jsonl(stdout: str, *, domain: str) -> list[dict[str, object]]:
    """Return in-scope passive subdomain discoveries with source attribution."""
    normalized_domain = domain.strip().lower().rstrip(".")
    findings: list[dict[str, object]] = []
    for line in (stdout or "").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        host = str(item.get("host", "")).strip().lower().rstrip(".")
        if not host or not (host == normalized_domain or host.endswith(f".{normalized_domain}")):
            continue
        sources = item.get("sources", item.get("source", ()))
        if isinstance(sources, str):
            sources = (sources,)
        if not isinstance(sources, list | tuple):
            sources = ()
        findings.append({"host": host, "sources": tuple(str(source) for source in sources if str(source).strip())})
    return findings
