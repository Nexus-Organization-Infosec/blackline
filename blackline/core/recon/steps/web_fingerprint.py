"""Domain-level HTTP technology fingerprinting step."""

from __future__ import annotations

from blackline.core.recon.models import ReconStep, ReconTarget


def web_fingerprint_step(target: ReconTarget) -> ReconStep:
    """Build a passive fingerprinting step for the normal HTTP target URLs."""
    return ReconStep(
        name="web_fingerprint",
        tool="fingerprint",
        inputs={
            "target": target.raw,
            "host": target.host,
            "scheme": target.scheme,
            "path": target.path,
            "port": target.port,
            "target_type": target.target_type,
        },
    )
