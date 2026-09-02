"""Domain-level TLS certificate inspection step."""

from __future__ import annotations

from blackline.core.recon.models import ReconStep, ReconTarget
from blackline.tools.tls.inspector import TlsInspectionResult, inspect_tls


def tls_inspection_step(target: ReconTarget) -> ReconStep:
    """Build a TLS inspection for the target's TLS endpoint."""
    port = target.port if target.target_type == "url" and target.port else "443"
    return ReconStep(
        name="tls_inspection",
        tool="tls",
        inputs={
            "target": target.raw,
            "host": target.host,
            "port": port,
            "server_name": target.host if target.target_type != "ip" else "",
            "target_type": target.target_type,
        },
    )


def execute_tls_step(target: ReconTarget) -> TlsInspectionResult:
    """Execute TLS inspection for one normalized target."""
    step = tls_inspection_step(target)
    return inspect_tls(
        str(step.inputs["host"]),
        port=int(str(step.inputs["port"])),
        server_name=str(step.inputs["server_name"]),
    )
