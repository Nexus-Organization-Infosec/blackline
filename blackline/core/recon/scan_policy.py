"""Explicit Nmap scan policies derived from recon strategy intent."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class NmapScanPolicy:
    """Baseline Nmap discovery behavior before user overrides are applied."""

    name: str
    profile: str
    ports: str = ""
    top_ports: str = ""
    timing: str = ""
    service_detection: bool = False
    os_detection: bool = False
    transport: str = "tcp"


NMAP_SCAN_POLICIES: dict[str, NmapScanPolicy] = {
    "surface": NmapScanPolicy("surface", "surface", top_ports="100"),
    "fast": NmapScanPolicy("fast", "fast", top_ports="1000", timing="T4"),
    "balanced": NmapScanPolicy("balanced", "balanced", top_ports="5000", timing="T3", service_detection=True),
    "quiet": NmapScanPolicy("quiet", "quiet", top_ports="1000", timing="T2", service_detection=True),
    "deep": NmapScanPolicy("deep", "deep", ports="all", timing="T4", service_detection=True, os_detection=True),
    "udp": NmapScanPolicy("udp", "udp", top_ports="100", transport="udp"),
}

_SPEED_TO_TIMING = {"low": "T2", "normal": "T3", "high": "T4", "aggressive": "T5"}


def nmap_scan_policy(params: dict[str, str]) -> NmapScanPolicy:
    """Resolve one named policy, treating UDP transport as an explicit policy choice."""
    requested = params.get("strategy", "").strip().lower()
    if params.get("transport", "").strip().lower() == "udp":
        requested = "udp"
    return NMAP_SCAN_POLICIES.get(requested, NMAP_SCAN_POLICIES["balanced"])


def nmap_policy_params(params: dict[str, str]) -> dict[str, str]:
    """Materialize policy defaults plus user overrides for the Nmap adapter."""
    policy = nmap_scan_policy(params)
    probe = params.get("probe", "").strip().lower()
    service_detection = _override_bool(params, ("service", "service_detection"), default=policy.service_detection)
    scripts = _override_bool(params, ("scripts",), default=False)
    os_detection = _override_bool(params, ("os", "os_detection"), default=policy.os_detection)
    if probe:
        service_detection = probe in {"service", "script", "fingerprint"}
        scripts = probe in {"script", "fingerprint"}
        os_detection = probe == "fingerprint"

    explicit_ports = params.get("ports", "").strip()
    explicit_top_ports = params.get("top_ports", "").strip()
    return {
        "ports": explicit_ports or ("" if explicit_top_ports else policy.ports),
        "top_ports": explicit_top_ports or ("" if explicit_ports else policy.top_ports),
        "profile": params.get("profile", "").strip() or policy.profile,
        "timing": params.get("timing", "").strip() or _SPEED_TO_TIMING.get(params.get("speed", "").strip().lower(), policy.timing),
        "service_detection": str(service_detection).lower(),
        "scripts": str(scripts).lower(),
        "os_detection": str(os_detection).lower(),
        "use_default_timing": str(policy.name not in {"surface", "udp"}).lower(),
        "transport": policy.transport,
        "strategy": policy.name,
    }


def _override_bool(params: dict[str, str], names: tuple[str, ...], *, default: bool) -> bool:
    for name in names:
        if name in params and params[name].strip():
            return params[name].strip().lower() in {"1", "true", "yes", "on"}
    return default
