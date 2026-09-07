"""Parse WhatWeb JSON logs into stable Blackline findings."""

from __future__ import annotations

import json


def parse_whatweb_json(raw_output: str) -> list[dict[str, object]]:
    """Normalize WhatWeb's JSON array while ignoring its trailing empty records."""
    try:
        raw_findings = json.loads(raw_output or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(raw_findings, list):
        return []

    findings: list[dict[str, object]] = []
    for raw in raw_findings:
        if not isinstance(raw, dict) or not raw.get("target"):
            continue
        plugins = raw.get("plugins", {})
        plugins = plugins if isinstance(plugins, dict) else {}
        findings.append(
            {
                "url": str(raw.get("target", "")),
                "status_code": _number(raw.get("http_status")),
                "title": _plugin_value(plugins, "Title"),
                "webserver": _plugin_value(plugins, "HTTPServer"),
                "technologies": tuple(str(name) for name in plugins if name not in {"Title", "HTTPServer"}),
                "plugins": tuple(str(name) for name in plugins),
            }
        )
    return findings


def _plugin_value(plugins: dict, name: str) -> str:
    details = plugins.get(name, {})
    if not isinstance(details, dict):
        return ""
    values = details.get("string", ())
    if isinstance(values, list) and values:
        return str(values[0])
    return ""


def _number(value: object) -> int | None:
    return int(value) if isinstance(value, int) or str(value).isdigit() else None
