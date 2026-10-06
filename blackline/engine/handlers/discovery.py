"""DNS, registration, and network-intelligence execution handlers."""

from __future__ import annotations

from blackline.engine.handlers.base import HandlerContext, artifact, call_with_optional_timeout, to_bool
from blackline.engine.models import PlanStep, StepResult
from blackline.tools.dns.resolver import resolve_dns
from blackline.tools.dns.subfinder import enumerate_subdomains
from blackline.tools.intel.rdap import resolve_rdap
from blackline.tools.intel.yougotmapped import resolve_ipintel


def execute_dns(step: PlanStep, context: HandlerContext) -> StepResult:
    lookup = call_with_optional_timeout(
        resolve_dns,
        step.params.get("host", "") or step.params.get("target", ""),
        command_executor=context.command_executor,
        timeout_seconds=step.timeout_seconds,
    )
    payload = {
        "target": step.params.get("target", ""),
        "host": lookup.host,
        "records": dict(lookup.records),
        "resolved_ips": list(lookup.resolved_ips),
        "provider": lookup.provider,
        "outcome": getattr(lookup, "outcome", ""),
        "negative_observation": getattr(lookup, "outcome", "") in {"no_data", "nxdomain"},
        "raw_output": lookup.raw_output,
        "elapsed_seconds": lookup.elapsed_seconds,
    }
    artifacts = [
        artifact(step, "host.ip", address, {"host": lookup.host}, provider=lookup.provider, confidence=1.0)
        for address in lookup.resolved_ips
    ]
    for record_type, values in lookup.records.items():
        artifacts.extend(
            artifact(
                step,
                "dns.record",
                lookup.host,
                {"type": record_type, "value": value},
                provider=lookup.provider,
                confidence=1.0,
            )
            for value in values
        )
    return StepResult(step.tool, step.action, lookup.ok, payload, lookup.error, artifacts=tuple(artifacts))


def execute_subfinder(step: PlanStep, context: HandlerContext) -> StepResult:
    result = enumerate_subdomains(
        step.params.get("domain", "") or step.params.get("target", ""),
        executor=context.command_executor,
        timeout_seconds=step.timeout_seconds,
    )
    payload = {
        "target": step.params.get("target", ""),
        "domain": result.domain,
        "subdomains": [
            {"host": finding.host, "sources": list(finding.sources)}
            for finding in result.subdomains
        ],
        "provider": "subfinder",
        "skipped": result.skipped,
        "negative_observation": result.negative_observation,
        "raw_output": result.raw_output,
        "elapsed_seconds": result.elapsed_seconds,
    }
    artifacts = tuple(
        artifact(
            step,
            "domain.subdomain",
            finding.host,
            {"sources": list(finding.sources)},
            provider="subfinder",
            confidence=0.8,
        )
        for finding in result.subdomains
    )
    return StepResult(step.tool, step.action, result.ok, payload, result.error, artifacts=artifacts)


def execute_ipintel(step: PlanStep, context: HandlerContext) -> StepResult:
    resolved_ips = [item.subject for item in context.evidence.find("host.ip")]
    lookup_ip = str(step.params.get("host", ""))
    if str(step.params.get("target_type", "")).lower() != "ip" and resolved_ips:
        lookup_ip = str(resolved_ips[0])
    intel = call_with_optional_timeout(
        resolve_ipintel,
        str(step.params.get("target", "")),
        lookup_ip=lookup_ip,
        deep=to_bool(step.params.get("deep", "")),
        timeout_seconds=step.timeout_seconds,
    )
    payload = {
        "target": step.params.get("target", ""),
        "lookup_ip": intel.lookup_ip,
        "asn": intel.asn,
        "org": intel.org,
        "domain": getattr(intel, "domain", ""),
        "location": intel.location,
        "latency": intel.latency,
        "vpn_likely": intel.vpn_likely,
        "confidence": intel.confidence,
        "jitter": intel.jitter,
        "bandwidth": intel.bandwidth,
        "mss": getattr(intel, "mss", None),
        "trace": list(intel.trace),
        "provider": intel.provider,
        "raw": dict(getattr(intel, "raw", {})),
        "elapsed_seconds": 0.0,
    }
    artifacts = []
    if intel.asn and str(intel.asn).lower() != "unknown":
        artifacts.append(artifact(step, "network.asn", intel.lookup_ip, {"asn": intel.asn}, provider=intel.provider, confidence=0.9))
    if intel.org and str(intel.org).lower() not in {"unknown", "private network"}:
        artifacts.append(artifact(step, "network.owner", intel.lookup_ip, {"organization": intel.org}, provider=intel.provider, confidence=0.8))
    return StepResult(step.tool, step.action, intel.ok, payload, intel.error, artifacts=tuple(artifacts))


def execute_rdap(step: PlanStep, context: HandlerContext) -> StepResult:
    resolved_ips = [item.subject for item in context.evidence.find("host.ip")]
    address = str(step.params.get("host", "")) if step.params.get("target_type") == "ip" else ""
    if not address and isinstance(resolved_ips, list) and resolved_ips:
        address = str(resolved_ips[0])
    domain = str(step.params.get("host", "")) if step.params.get("target_type") != "ip" else ""
    rdap = resolve_rdap(
        domain=domain,
        address=address,
        timeout_seconds=step.timeout_seconds if step.timeout_seconds is not None else 10.0,
    )
    payload = {
        "target": step.params.get("target", ""),
        "domain": rdap.domain,
        "registrar": rdap.registrar,
        "created": rdap.created,
        "expires": rdap.expires,
        "status": list(rdap.status),
        "address": rdap.address,
        "network": rdap.network,
        "organization": rdap.organization,
        "asn": rdap.asn,
        "provider": rdap.provider,
        "negative_observation": bool(getattr(rdap, "negative_observation", False)),
        "warnings": list(rdap.warnings),
        "raw": dict(rdap.raw),
        "elapsed_seconds": rdap.elapsed_seconds,
    }
    artifacts = []
    if rdap.domain:
        artifacts.append(artifact(step, "domain.registration", rdap.domain, {"registrar": rdap.registrar, "created": rdap.created, "expires": rdap.expires, "status": list(rdap.status)}, provider=rdap.provider, confidence=1.0))
    if rdap.organization:
        artifacts.append(artifact(step, "network.owner", rdap.address or domain, {"organization": rdap.organization, "network": rdap.network}, provider=rdap.provider, confidence=0.9))
    return StepResult(step.tool, step.action, rdap.ok, payload, rdap.error, artifacts=tuple(artifacts))


HANDLERS = (
    ("dns", execute_dns),
    ("subfinder", execute_subfinder),
    ("ipintel", execute_ipintel),
    ("rdap", execute_rdap),
)
