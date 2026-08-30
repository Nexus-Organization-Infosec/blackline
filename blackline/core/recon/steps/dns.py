"""Domain-level DNS step."""

from __future__ import annotations

from blackline.core.recon.models import ReconStep, ReconTarget
from blackline.tools.dns.resolver import DnsLookupResult, resolve_dns


def dns_step(target: ReconTarget) -> ReconStep:
    """Build the domain-level DNS step."""
    return ReconStep(
        name="dns",
        tool="dns",
        inputs={
            "target": target.raw,
            "host": target.host,
            "target_type": target.target_type,
        },
    )


def execute_dns_step(target: ReconTarget) -> DnsLookupResult:
    """Execute the DNS step for one normalized recon target."""
    return resolve_dns(target.host or target.raw)
