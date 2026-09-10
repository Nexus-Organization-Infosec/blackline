"""Parse ProjectDiscovery Naabu JSONL port discoveries."""

from __future__ import annotations

import json


def parse_naabu_jsonl(stdout: str) -> list[dict[str, object]]:
    """Return unique TCP port observations from valid Naabu JSON lines."""
    findings: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()
    for line in (stdout or "").splitlines():
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, dict):
            continue
        try:
            port = int(raw.get("port", 0))
        except (TypeError, ValueError):
            continue
        host = str(raw.get("host") or raw.get("ip") or "").strip()
        if not host or not 1 <= port <= 65535 or (host, port) in seen:
            continue
        seen.add((host, port))
        findings.append({"host": host, "port": port, "protocol": "tcp"})
    return sorted(findings, key=lambda item: (str(item["host"]), int(item["port"])))
