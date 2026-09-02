"""Domain-level RDAP registration and ownership step."""

from __future__ import annotations

from blackline.core.recon.models import ReconStep, ReconTarget


def rdap_step(target: ReconTarget) -> ReconStep:
    """Build one RDAP lookup after DNS data is available."""
    return ReconStep(
        name="rdap",
        tool="rdap",
        inputs={
            "target": target.raw,
            "host": target.host,
            "target_type": target.target_type,
        },
    )
