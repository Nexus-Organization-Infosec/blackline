"""Bounded web-crawl step."""

from __future__ import annotations

from blackline.core.recon.models import ReconStep, ReconTarget


def katana_crawl_step(target: ReconTarget) -> ReconStep:
    """Build a Katana step for a domain or explicit URL target."""
    return ReconStep(
        name="web_crawl",
        tool="katana",
        inputs={
            "target": target.raw,
            "host": target.host,
            "scheme": target.scheme,
            "path": target.path,
            "port": target.port,
            "target_type": target.target_type,
        },
    )
