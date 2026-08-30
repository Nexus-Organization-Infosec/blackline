"""Domain-level IP intelligence step."""

from __future__ import annotations

from blackline.core.recon.models import ReconStep, ReconTarget
from blackline.tools.intel.yougotmapped import IpIntelResult, resolve_ipintel


def ipintel_step(target: ReconTarget, params: dict[str, str] | None = None) -> ReconStep:
    """Build the IP intelligence enrichment step."""
    params = params or {}
    return ReconStep(
        name="ipintel",
        tool="ipintel",
        inputs={
            "target": target.raw,
            "host": target.host,
            "target_type": target.target_type,
            "deep": "true" if params.get("strategy", "").strip().lower() == "deep" else "",
        },
    )


def execute_ipintel_step(
    target: ReconTarget,
    *,
    lookup_ip: str = "",
    deep: bool = False,
) -> IpIntelResult:
    """Execute the curated IP intelligence step."""
    return resolve_ipintel(target.raw, lookup_ip=lookup_ip or target.host, deep=deep)
