"""Domain-level HTTP probing step."""

from __future__ import annotations

from blackline.core.recon.models import ReconStep, ReconTarget
from blackline.tools.http.client import HttpProbeResult, probe_http


def http_probe_step(target: ReconTarget) -> ReconStep:
    """Build the host-based HTTP probe step."""
    return ReconStep(
        name="http_probe",
        tool="http",
        inputs={
            "target": target.raw,
            "host": target.host,
            "scheme": target.scheme,
            "path": target.path,
            "port": target.port,
            "target_type": target.target_type,
        },
    )


def http_ip_probe_step(target: ReconTarget) -> ReconStep:
    """Build the direct IP HTTP probe step."""
    return ReconStep(
        name="http_ip_probe",
        tool="http",
        inputs={
            "target": target.raw,
            "host": target.host,
            "target_type": target.target_type,
        },
    )


def http_vhost_probe_step(target: ReconTarget) -> ReconStep:
    """Build the virtual-host HTTP probe step."""
    return ReconStep(
        name="http_vhost_probe",
        tool="http",
        inputs={
            "target": target.raw,
            "host": target.host,
            "target_type": target.target_type,
        },
    )


def execute_http_step(target: ReconTarget, *, mode: str) -> HttpProbeResult:
    """Execute the curated HTTP step for one normalized target."""
    return probe_http(
        target.raw,
        mode=mode,
        host=target.host,
        scheme=target.scheme,
        path=target.path,
        port=target.port,
    )
