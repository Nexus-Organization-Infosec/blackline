"""Source-aware correlation of normalized reconnaissance facts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True, slots=True)
class EvidenceClaim:
    """A concise fact and the tool providers that support it."""

    subject: str
    predicate: str
    value: str
    sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EvidenceGraph:
    """A normalized, source-aware graph built from a recon result set."""

    target: str
    claims: tuple[EvidenceClaim, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {"target": self.target, "claims": [asdict(claim) for claim in self.claims]}

    @property
    def sources(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(source for claim in self.claims for source in claim.sources))

    def values(self, predicate: str) -> tuple[str, ...]:
        return tuple(dict.fromkeys(claim.value for claim in self.claims if claim.predicate == predicate))


def build_evidence_graph(target: str, payloads: dict[str, dict]) -> EvidenceGraph:
    """Connect results while preserving the evidence source for every edge."""
    claims: list[EvidenceClaim] = []
    target = target.strip() or _target_from_payloads(payloads)
    dns = payloads.get("dns", {})
    subfinder = payloads.get("subfinder", {})
    rdap = payloads.get("rdap", {})
    ipintel = payloads.get("ipintel", {})
    fingerprint = payloads.get("fingerprint", {})
    httpx = payloads.get("httpx", {})
    whatweb = payloads.get("whatweb", {})
    rpcinfo = payloads.get("rpcinfo", {})
    sslyze = payloads.get("sslyze", {})
    tls = payloads.get("tls", {})

    dns_source = _sources(dns)
    records = dns.get("records", {}) if isinstance(dns, dict) else {}
    if isinstance(records, dict):
        for record_type in ("A", "AAAA"):
            values = records.get(record_type, [])
            if isinstance(values, list):
                for address in values:
                    _add_claim(claims, target, "resolves_to", str(address), dns_source)

    subfinder_source = _sources(subfinder, fallback="subfinder")
    subdomains = subfinder.get("subdomains", []) if isinstance(subfinder, dict) else []
    if isinstance(subdomains, list):
        for finding in subdomains:
            if not isinstance(finding, dict):
                continue
            host = str(finding.get("host", "")).strip()
            sources = finding.get("sources", [])
            finding_sources = tuple(str(source).strip() for source in sources if str(source).strip()) if isinstance(sources, list) else ()
            _add_claim(claims, target, "discovers_subdomain", host, finding_sources or subfinder_source)

    rdap_source = _sources(rdap, fallback="rdap.org")
    domain = str(rdap.get("domain", "")).strip() if isinstance(rdap, dict) else ""
    registrar = str(rdap.get("registrar", "")).strip() if isinstance(rdap, dict) else ""
    address = str(rdap.get("address", "")).strip() if isinstance(rdap, dict) else ""
    organization = str(rdap.get("organization", "")).strip() if isinstance(rdap, dict) else ""
    rdap_asn = str(rdap.get("asn", "")).strip() if isinstance(rdap, dict) else ""
    if domain:
        _add_claim(claims, target, "identifies_domain", domain, rdap_source)
    if registrar and registrar.lower() != "unknown":
        _add_claim(claims, domain or target, "registered_by", registrar, rdap_source)
    if address:
        _add_claim(claims, target, "resolves_to", address, rdap_source)
    if organization and organization.lower() != "unknown":
        _add_claim(claims, address or target, "owned_by", organization, rdap_source)
    if rdap_asn and rdap_asn.lower() != "unknown":
        _add_claim(claims, address or target, "announced_by", rdap_asn, rdap_source)

    intel_source = _sources(ipintel)
    lookup_ip = str(ipintel.get("lookup_ip", "")).strip() if isinstance(ipintel, dict) else ""
    intel_asn = str(ipintel.get("asn", "")).strip() if isinstance(ipintel, dict) else ""
    intel_org = str(ipintel.get("org", "")).strip() if isinstance(ipintel, dict) else ""
    if lookup_ip:
        _add_claim(claims, target, "resolves_to", lookup_ip, intel_source)
    if intel_asn and intel_asn.lower() != "unknown":
        _add_claim(claims, lookup_ip or target, "announced_by", intel_asn, intel_source)
    if intel_org and intel_org.lower() not in {"unknown", "private network"}:
        _add_claim(claims, lookup_ip or target, "owned_by", intel_org, intel_source)

    fingerprint_source = _sources(fingerprint, fallback="urllib")
    server = str(fingerprint.get("server", "")).strip() if isinstance(fingerprint, dict) else ""
    framework = str(fingerprint.get("framework", "")).strip() if isinstance(fingerprint, dict) else ""
    if server and server.lower() != "unknown":
        _add_claim(claims, target, "served_by", server, fingerprint_source)
    if framework and framework.lower() != "unknown":
        _add_claim(claims, target, "uses_framework", framework, fingerprint_source)

    httpx_source = _sources(httpx, fallback="httpx")
    httpx_findings = httpx.get("findings", []) if isinstance(httpx, dict) else []
    if isinstance(httpx_findings, list):
        for finding in httpx_findings:
            if not isinstance(finding, dict):
                continue
            webserver = str(finding.get("webserver", "")).strip()
            if webserver and webserver.lower() != "unknown":
                _add_claim(claims, target, "served_by", webserver, httpx_source)
            technologies = finding.get("technologies", [])
            if isinstance(technologies, list):
                for technology in technologies:
                    value = str(technology).strip()
                    if value and value.lower() != "unknown":
                        _add_claim(claims, target, "uses_technology", value, httpx_source)

    whatweb_source = _sources(whatweb, fallback="whatweb")
    whatweb_findings = whatweb.get("findings", []) if isinstance(whatweb, dict) else []
    if isinstance(whatweb_findings, list):
        for finding in whatweb_findings:
            if not isinstance(finding, dict):
                continue
            server = str(finding.get("webserver", "")).strip()
            if server and server.lower() != "unknown":
                _add_claim(claims, target, "served_by", server, whatweb_source)
            technologies = finding.get("technologies", [])
            if isinstance(technologies, list):
                for technology in technologies:
                    value = str(technology).strip()
                    if value and value.lower() != "unknown":
                        _add_claim(claims, target, "uses_technology", value, whatweb_source)

    rpcinfo_source = _sources(rpcinfo, fallback="rpcinfo")
    rpc_records = rpcinfo.get("registrations", []) if isinstance(rpcinfo, dict) else []
    if isinstance(rpc_records, list):
        for record in rpc_records:
            if not isinstance(record, dict):
                continue
            program = str(record.get("program", "")).strip()
            version = str(record.get("version", "")).strip()
            protocol = str(record.get("protocol", "")).strip()
            port = str(record.get("port", "")).strip()
            service = str(record.get("service", "")).strip()
            label = service or f"program {program} v{version}".strip()
            if label and port:
                _add_claim(claims, target, "exposes_rpc_service", f"{label} ({protocol}/{port})", rpcinfo_source)

    sslyze_source = _sources(sslyze, fallback="sslyze")
    sslyze_scans = sslyze.get("scans", []) if isinstance(sslyze, dict) else []
    if isinstance(sslyze_scans, list):
        for scan in sslyze_scans:
            if not isinstance(scan, dict):
                continue
            for protocol in scan.get("protocols", []):
                value = str(protocol).strip()
                if value:
                    _add_claim(claims, target, "supports_tls_protocol", value, sslyze_source)
            for finding in scan.get("findings", []):
                value = str(finding).strip()
                if value:
                    _add_claim(claims, target, "has_tls_finding", value, sslyze_source)

    tls_sources = _sources(tls, fallback="python ssl")
    parser = str(tls.get("certificate_parser", "")).strip() if isinstance(tls, dict) else ""
    if parser and parser not in tls_sources:
        tls_sources += (parser,)
    sans = tls.get("sans", []) if isinstance(tls, dict) else []
    if isinstance(sans, list):
        for san in sans:
            name = str(san).removeprefix("DNS:").strip()
            if name:
                _add_claim(claims, target, "presents_tls_name", name, tls_sources)

    return EvidenceGraph(target, tuple(claims))


def _add_claim(claims: list[EvidenceClaim], subject: str, predicate: str, value: str, sources: tuple[str, ...]) -> None:
    if not subject or not value:
        return
    candidate = EvidenceClaim(subject, predicate, value, sources)
    for index, existing in enumerate(claims):
        if (existing.subject, existing.predicate, existing.value) == (candidate.subject, candidate.predicate, candidate.value):
            claims[index] = EvidenceClaim(existing.subject, existing.predicate, existing.value, tuple(dict.fromkeys((*existing.sources, *sources))))
            return
    claims.append(candidate)


def _sources(payload: object, *, fallback: str = "") -> tuple[str, ...]:
    provider = str(payload.get("provider", "")).strip() if isinstance(payload, dict) else ""
    return (provider or fallback,) if provider or fallback else ()


def _target_from_payloads(payloads: dict[str, dict]) -> str:
    for payload in payloads.values():
        if isinstance(payload, dict):
            target = str(payload.get("target", "")).strip()
            if target:
                return target
    return ""
