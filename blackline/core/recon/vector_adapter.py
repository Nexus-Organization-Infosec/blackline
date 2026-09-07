"""Recon's configuration-backed bridge to the generic Vector subsystem."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from blackline.clt.ir import ConditionIntent
from blackline.config.tool_loader import get_vector_config
from blackline.engine.context import ExecutionContext
from blackline.engine.executor import StepResult
from blackline.engine.planner import ExecutionPlan, build_followup_plan
from blackline.vector import Capability, Decision, Goal, Observation, Policy, Vector


@dataclass(frozen=True, slots=True)
class InvestigationRound:
    """One recon execution round plus the public Vector decision summary."""

    number: int
    discovery: bool
    results: tuple[StepResult, ...]
    decision: Decision


def create_recon_vector(context: ExecutionContext) -> Vector:
    """Build Vector from recon policy/catalog configuration, not code constants."""
    strategy = context.params.get("strategy", "balanced").strip().lower() or "balanced"
    goal = Goal("recon", context.normalized_target.host if context.normalized_target else context.params.get("target", ""), strategy, context.params)
    vector = Vector(goal, policy=recon_policy(strategy, context.params))
    for capability in recon_capabilities(context.params):
        vector.register_capability(capability)
    return vector


def recon_policy(strategy: str, params: dict[str, str]) -> Policy:
    """Resolve strategy and explicit transport constraints from configuration."""
    config = get_vector_config("recon")
    strategies = config.get("strategies", {}) if isinstance(config.get("strategies"), dict) else {}
    selected = strategies.get(strategy, strategies.get("balanced", {}))
    selected = selected if isinstance(selected, dict) else {}
    actions = selected.get("allowed_actions", ())
    allowed = frozenset(str(action) for action in actions) if isinstance(actions, list) else frozenset()
    max_actions = _positive_int(selected.get("max_actions_per_round"), default=3)

    transport = params.get("transport", "").strip().lower()
    overrides = config.get("overrides", {}) if isinstance(config.get("overrides"), dict) else {}
    transport_overrides = overrides.get("transport", {}) if isinstance(overrides.get("transport"), dict) else {}
    override = transport_overrides.get(transport, {}) if isinstance(transport_overrides.get(transport, {}), dict) else {}
    if "max_actions_per_round" in override:
        max_actions = _positive_int(override.get("max_actions_per_round"), default=max_actions, allow_zero=True)
    return Policy(
        allowed_actions=allowed,
        max_actions_per_round=max_actions,
        cost_weight=_integer(selected.get("cost_weight", 1)),
    )


def recon_round_limit(strategy: str) -> int:
    """Return the configured decision-cycle budget for a strategy."""
    config = get_vector_config("recon")
    strategies = config.get("strategies", {}) if isinstance(config.get("strategies"), dict) else {}
    selected = strategies.get(strategy, strategies.get("balanced", {}))
    return _positive_int(selected.get("max_decision_rounds") if isinstance(selected, dict) else None, default=3)


def recon_capabilities(params: dict[str, str]) -> tuple[Capability, ...]:
    """Build configured recon capabilities while honoring explicit overrides."""
    udp_only = params.get("transport", "").strip().lower() == "udp"
    config = get_vector_config("recon")
    entries = config.get("capabilities", ())
    if not isinstance(entries, list):
        return ()
    probe = params.get("probe", "").strip().lower()
    capabilities: list[Capability] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        verb, subject = str(entry.get("verb", "")), str(entry.get("subject", ""))
        if udp_only and verb != "collect":
            continue
        if probe in {"surface", "service"} and verb != "probe":
            continue
        requirements = _requirements(entry.get("requires", ()))
        if not verb or not subject or not requirements:
            continue
        capabilities.append(
            Capability.for_action(
                verb,
                subject,
                requires=requirements,
                priority=_integer(entry.get("priority")),
                cost=_integer(entry.get("cost")),
                risk=_integer(entry.get("risk")),
            )
        )
    return tuple(capabilities)


def observations_from_results(results: Iterable[StepResult], *, fallback_host: str) -> tuple[Observation, ...]:
    """Normalize recon evidence and derive provenance-linked semantic tags."""
    observations: list[Observation] = []
    for result_index, result in enumerate(results):
        payload = result.payload if isinstance(result.payload, dict) else {}
        source = str(payload.get("provider", result.tool) or result.tool)
        if result.tool == "nmap":
            host = str(payload.get("target", "") or fallback_host)
            ports = payload.get("ports", ())
            ports = ports if isinstance(ports, list) else ()
            open_services = 0
            for port_data in ports:
                if not isinstance(port_data, dict):
                    continue
                try:
                    port = int(port_data.get("port", 0))
                except (TypeError, ValueError):
                    continue
                protocol = normalize_service_protocol(str(port_data.get("service", "")), port)
                state = str(port_data.get("state", "unknown")).lower()
                observed = Observation.service(host=host, port=port, protocol=protocol, state=state, source=source, confidence=0.98, version=str(port_data.get("version", "")))
                observations.append(observed)
                if state == "open" and protocol in {"http", "https"}:
                    open_services += 1
                    observations.append(_tag("web", f"{host}:{port}", "possible", source, 0.9, (observed.identifier,)))
                elif state == "open":
                    open_services += 1
            discovery_state = "failed" if not result.ok else "no_services" if not open_services else "available"
            observations.append(_tag("discovery", "nmap", discovery_state, source, 0.9 if result.ok else 0.7, (f"nmap:{result_index}",)))
        elif result.tool == "http":
            for finding_index, finding in enumerate(payload.get("findings", ())):
                if isinstance(finding, dict):
                    observations.append(_tag("web", str(finding.get("url", "") or fallback_host), "reachable" if finding.get("ok") else "closed", source, 0.95 if finding.get("ok") else 0.8, (f"http:{result_index}:{finding_index}",)))
        elif result.tool == "httpx":
            for finding_index, finding in enumerate(payload.get("findings", ())):
                if not isinstance(finding, dict):
                    continue
                endpoint = str(finding.get("url", "") or fallback_host)
                observations.append(_tag("web", endpoint, "reachable", source, 0.95, (f"httpx:{result_index}:{finding_index}",)))
                for technology in finding.get("technologies", ()):
                    value = str(technology).strip().lower()
                    if value:
                        observations.append(_tag("technology", value, "found", source, 0.8, (f"httpx:{result_index}:{finding_index}",)))
        elif result.tool == "whatweb":
            for finding_index, finding in enumerate(payload.get("findings", ())):
                if not isinstance(finding, dict):
                    continue
                for technology in finding.get("technologies", ()):
                    value = str(technology).strip().lower()
                    if value:
                        observations.append(_tag("technology", value, "found", source, 0.85, (f"whatweb:{result_index}:{finding_index}",)))
        elif result.tool == "rpcinfo":
            for registration_index, registration in enumerate(payload.get("registrations", ())):
                if not isinstance(registration, dict):
                    continue
                program = str(registration.get("program", "")).strip()
                port = str(registration.get("port", "")).strip()
                if program and port:
                    observations.append(_tag("rpc_program", f"{program}:{port}", "registered", source, 0.95, (f"rpcinfo:{result_index}:{registration_index}",)))
        elif result.tool == "dns":
            records = payload.get("records", {})
            if isinstance(records, dict):
                for record_type in ("A", "AAAA"):
                    for address in records.get(record_type, ()):
                        observations.append(_tag("address", str(address), "found", source, 0.95, (f"dns:{result_index}:{record_type}",)))
        elif result.tool == "fingerprint" and result.ok:
            for field, entity in (("framework", "framework"), ("server", "server"), ("javascript", "runtime")):
                value = str(payload.get(field, "")).strip()
                if value and value.lower() != "unknown":
                    observations.append(_tag(entity, value.lower(), "found", source, 0.8, (f"fingerprint:{result_index}",)))
        elif result.tool == "tls":
            observations.append(_tag("tls", f"{payload.get('host', fallback_host)}:{payload.get('port', 443)}", "valid" if result.ok else "unavailable", source, 0.9 if result.ok else 0.6, (f"tls:{result_index}",)))
        elif result.tool == "ipintel":
            asn = str(payload.get("asn", "")).strip()
            if asn and asn.lower() != "unknown":
                observations.append(_tag("asn", asn, "found", source, 0.75, (f"ipintel:{result_index}",)))
        elif result.tool == "rdap":
            organization = str(payload.get("organization", "")).strip()
            if organization and organization.lower() != "unknown":
                observations.append(_tag("network_owner", organization.lower(), "found", source, 0.8, (f"rdap:{result_index}",)))
    return tuple(observations)


def execute_followup_plan(context: ExecutionContext, decision: Decision) -> ExecutionPlan:
    """Delegate concrete tool request selection to the engine planner."""
    return build_followup_plan(context, decision.selected)


def normalize_service_protocol(service: str, port: int) -> str:
    """Apply recon-owned, configurable service normalization."""
    config = get_vector_config("recon").get("service_normalization", {})
    config = config if isinstance(config, dict) else {}
    value = service.strip().lower()
    https = {str(item).lower() for item in config.get("https_services", ())}
    web_ports = {int(item) for item in config.get("web_default_ports", ()) if str(item).isdigit()}
    if value in https or (port == 443 and "http" in value):
        return "https"
    if "http" in value or (port in web_ports and value in {"", "unknown"}):
        return "http"
    return value or "unknown"


def _requirements(raw: object) -> tuple[ConditionIntent, ...]:
    if not isinstance(raw, list):
        return ()
    requirements: list[ConditionIntent] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        entity, value, state = (str(item.get(key, "")).lower() for key in ("entity", "value", "state"))
        if entity and value and state:
            requirements.append(ConditionIntent(entity, value, state))
    return tuple(requirements)


def _tag(entity: str, value: str, state: str, source: str, confidence: float, evidence: tuple[str, ...]) -> Observation:
    return Observation("tag", {"entity": entity, "value": value, "state": state}, source, confidence=confidence, origin="derived", source_evidence=evidence)


def _integer(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _positive_int(value: object, *, default: int, allow_zero: bool = False) -> int:
    candidate = _integer(value)
    if candidate > 0 or allow_zero and candidate == 0:
        return candidate
    return default
