"""Domain-level port scan step."""

from __future__ import annotations

from blackline.core.recon.models import ReconStep, ReconTarget


def port_scan_step(target: ReconTarget, params: dict[str, str]) -> ReconStep:
    """Build the port scan step with recon-facing parameters."""
    return ReconStep(
        name="port_scan",
        tool="nmap",
        inputs={
            "target": target.scan_target,
            "target_type": target.target_type,
            "ports": params.get("ports", "1-1024"),
            "top_ports": params.get("top_ports", ""),
            "strategy": params.get("strategy", ""),
            "speed": params.get("speed", ""),
            "probe": params.get("probe", ""),
            "transport": params.get("transport", ""),
            "profile": params.get("profile", ""),
            "timing": params.get("timing", ""),
            "service": params.get("service", ""),
            "service_detection": params.get("service_detection", ""),
            "scripts": params.get("scripts", ""),
            "os": params.get("os", ""),
            "os_detection": params.get("os_detection", ""),
        },
    )


def port_state_counts(ports: list[dict[str, object]]) -> dict[str, int]:
    """Count notable port states in a normalized port list."""
    counts = {"open": 0, "filtered": 0, "interesting": 0}
    for port in ports:
        if not isinstance(port, dict):
            continue
        state = str(port.get("state", "")).strip().lower()
        if not state:
            continue
        if state == "open":
            counts["open"] += 1
        elif state == "filtered":
            counts["filtered"] += 1
        if state in {"open", "filtered"}:
            counts["interesting"] += 1
    return counts
