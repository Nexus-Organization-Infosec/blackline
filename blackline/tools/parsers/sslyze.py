"""Extract stable TLS configuration facts from SSLyze JSON output."""

from __future__ import annotations

import json


def parse_sslyze_json(raw_output: str) -> list[dict[str, object]]:
    """Normalize completed SSLyze scans while tolerating schema evolution."""
    try:
        document = json.loads(raw_output or "{}")
    except json.JSONDecodeError:
        return []
    results = document.get("server_scan_results", []) if isinstance(document, dict) else []
    if not isinstance(results, list):
        return []
    findings: list[dict[str, object]] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        location = item.get("server_location", {})
        scan = item.get("scan_result", {})
        if not isinstance(location, dict) or not isinstance(scan, dict):
            continue
        hostname = str(location.get("hostname", "")).strip()
        port = _number(location.get("port"))
        if not hostname:
            continue
        protocols: list[str] = []
        ciphers: list[str] = []
        for key, value in scan.items():
            if not isinstance(value, dict) or value.get("status") != "COMPLETED":
                continue
            protocol = _protocol_name(key)
            accepted = _accepted_ciphers(value.get("result"))
            if protocol and accepted:
                protocols.append(protocol)
                ciphers.extend(accepted)
        findings.append(
            {
                "host": hostname,
                "port": port,
                "protocols": tuple(dict.fromkeys(protocols)),
                "ciphers": tuple(dict.fromkeys(ciphers)),
                "findings": tuple(_security_findings(scan)),
            }
        )
    return findings


def _protocol_name(key: str) -> str:
    normalized = key.lower()
    if not normalized.startswith("tls_") or not normalized.endswith("_cipher_suites"):
        return ""
    version = normalized.removeprefix("tls_").removesuffix("_cipher_suites").replace("_", ".")
    return f"TLS {version}"


def _accepted_ciphers(value: object) -> list[str]:
    if not isinstance(value, dict):
        return []
    accepted = value.get("accepted_cipher_suites", [])
    if not isinstance(accepted, list):
        return []
    names: list[str] = []
    for item in accepted:
        if not isinstance(item, dict):
            continue
        cipher = item.get("cipher_suite", {})
        if isinstance(cipher, dict):
            name = str(cipher.get("name", "")).strip()
            if name:
                names.append(name)
    return names


def _security_findings(scan: dict) -> list[str]:
    labels = {
        "heartbleed": "Heartbleed vulnerable",
        "robot": "ROBOT vulnerable",
        "openssl_ccs_injection": "OpenSSL CCS injection vulnerable",
        "crime": "CRIME vulnerable",
    }
    findings: list[str] = []
    for key, label in labels.items():
        command = scan.get(key, {})
        if not isinstance(command, dict) or command.get("status") != "COMPLETED":
            continue
        if _contains_vulnerability(command.get("result")):
            findings.append(label)
    return findings


def _contains_vulnerability(value: object) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.startswith("is_vulnerable") and item is True:
                return True
            if _contains_vulnerability(item):
                return True
    elif isinstance(value, list):
        return any(_contains_vulnerability(item) for item in value)
    return False


def _number(value: object) -> int | None:
    return int(value) if isinstance(value, int) or str(value).isdigit() else None
