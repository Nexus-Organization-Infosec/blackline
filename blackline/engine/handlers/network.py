"""Port, service, RPC, and SMB execution handlers."""

from __future__ import annotations

from blackline.core.recon.steps.port_scan import port_state_counts
from blackline.engine.handlers.base import HandlerContext, artifact, to_bool, to_port
from blackline.engine.models import PlanStep, StepResult
from blackline.tools.network.naabu import scan_ports_with_naabu
from blackline.tools.network.nmap import NmapRequest, display_command
from blackline.tools.network.nmap import execute_nmap as run_nmap
from blackline.tools.network.rpcinfo import query_rpcinfo
from blackline.tools.network.smbclient import enumerate_smb_shares


def execute_rpcinfo(step: PlanStep, context: HandlerContext) -> StepResult:
    result = query_rpcinfo(
        str(step.params.get("host") or step.params.get("target") or ""),
        timeout_seconds=step.timeout_seconds or 12.0,
        executor=context.command_executor,
    )
    payload = {
        "target": result.target,
        "provider": "rpcinfo",
        "registrations": [
            {
                "program": item.program,
                "version": item.version,
                "protocol": item.protocol,
                "port": item.port,
                "service": item.service,
            }
            for item in result.registrations
        ],
        "skipped": result.skipped,
        "negative_observation": result.negative_observation,
        "raw_output": result.raw_output,
        "elapsed_seconds": result.elapsed_seconds,
    }
    artifacts = tuple(
        artifact(
            step,
            "rpc.program",
            result.target,
            {"program": item.program, "version": item.version, "protocol": item.protocol, "port": item.port, "service": item.service},
            provider="rpcinfo",
            confidence=1.0,
        )
        for item in result.registrations
    )
    return StepResult(step.tool, step.action, result.ok, payload, result.error, artifacts=artifacts)


def execute_smbclient(step: PlanStep, context: HandlerContext) -> StepResult:
    result = enumerate_smb_shares(
        str(step.params.get("host") or step.params.get("target") or ""),
        port=to_port(step.params.get("port") or "445"),
        timeout_seconds=step.timeout_seconds or 15.0,
        executor=context.command_executor,
    )
    payload = {
        "target": result.target,
        "port": result.port,
        "provider": "smbclient",
        "shares": [
            {"name": share.name, "type": share.type, "comment": share.comment}
            for share in result.shares
        ],
        "skipped": result.skipped,
        "negative_observation": result.negative_observation,
        "warnings": list(result.warnings),
        "raw_output": result.raw_output,
        "elapsed_seconds": result.elapsed_seconds,
    }
    artifacts = tuple(
        artifact(step, "smb.share", result.target, {"name": share.name, "type": share.type, "comment": share.comment, "port": result.port}, provider="smbclient", confidence=1.0)
        for share in result.shares
    )
    return StepResult(step.tool, step.action, result.ok, payload, result.error, artifacts=artifacts)


def execute_naabu(step: PlanStep, context: HandlerContext) -> StepResult:
    result = scan_ports_with_naabu(
        str(step.params.get("target", "")),
        ports=str(step.params.get("ports", "")),
        top_ports=str(step.params.get("top_ports", "")),
        timeout_seconds=step.timeout_seconds or 60.0,
        executor=context.command_executor,
    )
    payload = {
        "target": result.target,
        "provider": "naabu",
        "ports": [
            {"host": item.host, "port": item.port, "protocol": item.protocol, "state": "open"}
            for item in result.ports
        ],
        "skipped": result.skipped,
        "negative_observation": result.negative_observation,
        "complete": bool(getattr(result, "complete", True)),
        "warnings": list(getattr(result, "warnings", ())),
        "raw_output": result.raw_output,
        "elapsed_seconds": result.elapsed_seconds,
    }
    artifacts = [
        artifact(
            step,
            "scan.port_discovery",
            result.target,
            {"complete": bool(getattr(result, "complete", True)), "found": len(result.ports)},
            provider="naabu",
            confidence=1.0,
        )
    ]
    artifacts.extend(
        artifact(step, "host.port", item.host or result.target, {"port": item.port, "protocol": item.protocol, "state": "open"}, provider="naabu", confidence=0.95)
        for item in result.ports
    )
    return StepResult(step.tool, step.action, result.ok, payload, result.error, artifacts=tuple(artifacts))


def execute_nmap(step: PlanStep, context: HandlerContext) -> StepResult:
    discoveries = context.evidence.find("scan.port_discovery", source_provider="naabu")
    discovery = discoveries[-1] if discoveries else None
    naabu_ports = context.evidence.find("host.port", source_provider="naabu")
    if discovery is not None and discovery.data.get("complete") and not naabu_ports:
        return StepResult(
            step.tool,
            step.action,
            ok=False,
            payload={
                "target": step.params.get("target", ""),
                "ports": [],
                "provider": "nmap",
                "skipped": True,
                "skip_reason": "Naabu found no open TCP ports",
                "negative_observation": True,
            },
            error="Naabu found no open TCP ports",
        )
    discovered_ports = _nmap_ports_from_naabu(naabu_ports) if discovery is not None and discovery.data.get("complete") else ""
    request = NmapRequest(
        target=step.params.get("target", ""),
        ports=discovered_ports or step.params.get("ports", ""),
        top_ports="" if discovered_ports else step.params.get("top_ports", ""),
        profile=step.params.get("profile", "default"),
        timing=step.params.get("timing", ""),
        service_detection=to_bool(step.params.get("service_detection", "")),
        scripts=to_bool(step.params.get("scripts", "")),
        os_detection=to_bool(step.params.get("os_detection", "")),
        use_default_timing=to_bool(step.params.get("use_default_timing", "true")),
    )
    try:
        execution = run_nmap(
            request,
            executor=context.command_executor,
            timeout_seconds=step.timeout_seconds,
        )
    except TypeError:
        execution = run_nmap(request, executor=context.command_executor)
    payload = {
        "provider": "nmap",
        "command": list(display_command(execution.command)),
        "target": execution.parsed.target,
        "host_status": execution.parsed.host_status,
        "raw_output": execution.parsed.raw_output,
        "ports": [
            {
                "port": port.port,
                "protocol": port.protocol,
                "state": port.state,
                "service": port.service,
                **({"version": port.version} if port.version else {}),
            }
            for port in execution.parsed.ports
        ],
        "warnings": list(execution.parsed.warnings),
        "negative_observation": execution.ok and not any(
            str(port.state).lower() in {"open", "filtered"}
            for port in execution.parsed.ports
        ),
        "system": {
            "device": getattr(execution.parsed, "device_type", ""),
            "os": getattr(execution.parsed, "operating_system", ""),
            "kernel": getattr(execution.parsed, "kernel", ""),
            "cpe": getattr(execution.parsed, "cpe", ""),
            "distance": getattr(execution.parsed, "distance", ""),
        },
    }
    counts = port_state_counts(payload["ports"])
    artifacts = []
    for port in execution.parsed.ports:
        artifacts.append(artifact(step, "host.port", execution.parsed.target, {"port": port.port, "protocol": port.protocol, "state": port.state}, provider="nmap", confidence=1.0))
        if port.service:
            artifacts.append(artifact(step, "service", execution.parsed.target, {"port": port.port, "protocol": port.protocol, "name": port.service, "version": port.version}, provider="nmap", confidence=0.9))
    system = payload["system"]
    if isinstance(system, dict) and any(system.values()):
        artifacts.append(artifact(step, "system", execution.parsed.target, dict(system), provider="nmap", confidence=0.7))
    return StepResult(
        step.tool,
        step.action,
        execution.ok,
        {
            **payload,
            "open_ports": counts["open"],
            "filtered_ports": counts["filtered"],
            "interesting_ports": counts["interesting"],
            "elapsed_seconds": execution.elapsed_seconds,
        },
        execution.error or execution.stderr,
        artifacts=tuple(artifacts),
    )


def _nmap_ports_from_naabu(value: tuple[object, ...]) -> str:
    ports: set[int] = set()
    for item in value:
        data = getattr(item, "data", {})
        if not isinstance(data, dict) or str(data.get("protocol", "tcp")).lower() != "tcp":
            continue
        try:
            port = int(data.get("port", 0))
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    return ",".join(str(port) for port in sorted(ports))


HANDLERS = (
    ("rpcinfo", execute_rpcinfo),
    ("smbclient", execute_smbclient),
    ("naabu", execute_naabu),
    ("nmap", execute_nmap),
)
