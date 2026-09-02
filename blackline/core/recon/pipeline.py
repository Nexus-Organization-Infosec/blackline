"""Recon pipeline definitions."""

from __future__ import annotations

from dataclasses import dataclass, field

from blackline.core.recon.models import ReconStep, ReconTarget, normalize_recon_target
from blackline.core.recon.steps.dns import dns_step
from blackline.core.recon.steps.http import http_ip_probe_step, http_probe_step
from blackline.core.recon.steps.ipintel import ipintel_step
from blackline.core.recon.steps.port_scan import port_scan_step
from blackline.core.recon.steps.rdap import rdap_step
from blackline.core.recon.steps.tls import tls_inspection_step
from blackline.core.recon.steps.web_fingerprint import web_fingerprint_step


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
    if target.target_type == "ip":
        return (
            ReconStep(name="reverse_dns", tool="reverse_dns", inputs={"target": target.host}),
            ipintel_step(target, params),
            http_ip_probe_step(target),
            web_fingerprint_step(target),
            tls_inspection_step(target),
            rdap_step(target),
            port_scan_step(target, params),
        )

    if target.target_type == "domain":
        return (
            dns_step(target),
            ipintel_step(target, params),
            http_probe_step(target),
            web_fingerprint_step(target),
            tls_inspection_step(target),
            rdap_step(target),
            port_scan_step(target, params),
        )

    if target.target_type == "url":
        steps = (
            http_probe_step(target),
            web_fingerprint_step(target),
            dns_step(target),
            ipintel_step(target, params),
        )
        if target.scheme == "https" or target.port == "443":
            steps += (tls_inspection_step(target),)
        return steps + (rdap_step(target), port_scan_step(target, params))

    return ()
