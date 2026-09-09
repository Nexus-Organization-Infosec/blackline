"""Recon step construction for SSLyze TLS configuration analysis."""

from __future__ import annotations

from blackline.core.recon.models import ReconStep, ReconTarget


def sslyze_step(target: ReconTarget) -> ReconStep:
    """Build a TLS configuration scan for the target's explicit or HTTPS port."""
    port = target.port or "443"
    return ReconStep(
        name="sslyze",
        tool="sslyze",
        inputs={"host": target.host, "port": port, "target_type": target.target_type},
    )
