"""Recon step construction for passive domain discovery."""

from __future__ import annotations

from blackline.core.recon.models import ReconStep, ReconTarget


def subfinder_step(target: ReconTarget) -> ReconStep:
    """Build passive subdomain enumeration for a normalized root domain."""
    return ReconStep(name="subfinder", tool="subfinder", inputs={"domain": target.host, "target": target.host})
