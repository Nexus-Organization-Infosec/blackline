"""Recon pipeline definitions."""

from __future__ import annotations

from dataclasses import dataclass, field

from blackline.core.recon.models import ReconStep, ReconTarget, normalize_recon_target
from blackline.core.recon.steps.dns import dns_step
from blackline.core.recon.steps.http import http_ip_probe_step, http_probe_step, httpx_probe_step
from blackline.core.recon.steps.ipintel import ipintel_step
from blackline.core.recon.steps.katana import katana_crawl_step
from blackline.core.recon.steps.port_scan import port_scan_step
from blackline.core.recon.steps.rdap import rdap_step
from blackline.core.recon.steps.rpcinfo import rpcinfo_step
from blackline.core.recon.steps.subfinder import subfinder_step
from blackline.core.recon.steps.tls import tls_inspection_step
from blackline.core.recon.steps.sslyze import sslyze_step
from blackline.core.recon.steps.web_fingerprint import web_fingerprint_step, whatweb_fingerprint_step

PROFILE_TOOLS: dict[str, frozenset[str]] = {
    # Surface and fast still take a deliberately bounded Nmap snapshot.
    "surface": frozenset({"dns", "subfinder", "http", "httpx", "fingerprint", "whatweb", "katana", "tls", "sslyze", "rdap", "rpcinfo", "nmap"}),
    "fast": frozenset({"dns", "subfinder", "http", "httpx", "fingerprint", "whatweb", "katana", "tls", "sslyze", "rdap", "rpcinfo", "nmap"}),
    # These profiles keep Blackline's independent evidence layers available.
    "balanced": frozenset({"dns", "subfinder", "ipintel", "http", "httpx", "fingerprint", "whatweb", "katana", "tls", "sslyze", "rdap", "rpcinfo", "nmap"}),
    "quiet": frozenset({"dns", "subfinder", "ipintel", "http", "httpx", "fingerprint", "whatweb", "katana", "tls", "sslyze", "rdap", "rpcinfo", "nmap"}),
    "deep": frozenset({"dns", "subfinder", "ipintel", "http", "httpx", "fingerprint", "whatweb", "katana", "tls", "sslyze", "rdap", "rpcinfo", "nmap"}),
    "udp": frozenset({"dns", "subfinder", "ipintel", "http", "httpx", "fingerprint", "whatweb", "katana", "tls", "sslyze", "rdap", "rpcinfo", "nmap"}),
}
PROFILE_TOOLS["auto"] = PROFILE_TOOLS["balanced"]


@dataclass(frozen=True, slots=True)
class ReconPipeline:
    """Ordered set of recon steps for one normalized target."""

    target: ReconTarget
    steps: tuple[ReconStep, ...] = field(default_factory=tuple)


def build_recon_pipeline(raw_target: str, *, params: dict[str, str] | None = None) -> ReconPipeline:
    """Build the normalized recon pipeline for one target."""
    params = params or {}
    target = normalize_recon_target(raw_target)
    return ReconPipeline(target=target, steps=_steps_for_target(target, params))


def _steps_for_target(target: ReconTarget, params: dict[str, str]) -> tuple[ReconStep, ...]:
    profile = recon_profile_name(params)
    if target.target_type == "ip":
        steps = (
            ReconStep(name="reverse_dns", tool="reverse_dns", inputs={"target": target.host}),
            ipintel_step(target, params),
            http_ip_probe_step(target),
            httpx_probe_step(target),
            web_fingerprint_step(target),
            whatweb_fingerprint_step(target),
            tls_inspection_step(target),
            sslyze_step(target),
            rdap_step(target),
            rpcinfo_step(target),
            port_scan_step(target, params),
        )
        return _select_profile_steps(steps, profile)

    if target.target_type == "domain":
        steps = (
            dns_step(target),
            subfinder_step(target),
            ipintel_step(target, params),
            http_probe_step(target),
            httpx_probe_step(target),
            web_fingerprint_step(target),
            whatweb_fingerprint_step(target),
            katana_crawl_step(target),
            tls_inspection_step(target),
            sslyze_step(target),
            rdap_step(target),
            rpcinfo_step(target),
            port_scan_step(target, params),
        )
        return _select_profile_steps(steps, profile)

    if target.target_type == "url":
        steps = (
            http_probe_step(target),
            httpx_probe_step(target),
            web_fingerprint_step(target),
            whatweb_fingerprint_step(target),
            katana_crawl_step(target),
            dns_step(target),
            ipintel_step(target, params),
        )
        if target.scheme == "https" or target.port == "443":
            steps += (tls_inspection_step(target), sslyze_step(target))
        return _select_profile_steps(steps + (rdap_step(target), port_scan_step(target, params)), profile)

    return ()


def recon_profile_name(params: dict[str, str]) -> str:
    """Return the evidence-selection profile; Nmap details live in scan policy."""
    requested = params.get("strategy", "").strip().lower()
    return requested if requested in PROFILE_TOOLS else "balanced"


def _select_profile_steps(steps: tuple[ReconStep, ...], profile: str) -> tuple[ReconStep, ...]:
    enabled_tools = PROFILE_TOOLS[profile]
    return tuple(step for step in steps if step.tool == "reverse_dns" or step.tool in enabled_tools)
