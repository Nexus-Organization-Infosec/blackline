"""Fast TCP discovery step."""

from __future__ import annotations

from blackline.core.recon.models import ReconStep, ReconTarget


def naabu_scan_step(target: ReconTarget, params: dict[str, str]) -> ReconStep:
    """Build a fast port-discovery request ahead of Nmap enrichment."""
    return ReconStep(
        name="fast_port_discovery",
        tool="naabu",
        inputs={
            "target": target.scan_target,
            "target_type": target.target_type,
            "ports": params.get("ports", ""),
            "top_ports": params.get("top_ports", ""),
        },
    )
