"""Recon step construction for portmapper/RPC registry enumeration."""

from __future__ import annotations

from blackline.core.recon.models import ReconStep, ReconTarget


def rpcinfo_step(target: ReconTarget) -> ReconStep:
    """Build a bounded query for registered RPC programs on the target host."""
    return ReconStep(
        name="rpcinfo",
        tool="rpcinfo",
        inputs={"target": target.host, "host": target.host, "target_type": target.target_type},
    )
