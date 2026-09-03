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
    rdap = payloads.get("rdap", {})
    ipintel = payloads.get("ipintel", {})
    fingerprint = payloads.get("fingerprint", {})
    tls = payloads.get("tls", {})

    dns_source = _sources(dns)
    records = dns.get("records", {}) if isinstance(dns, dict) else {}
    if isinstance(records, dict):
        for record_type in ("A", "AAAA"):
            values = records.get(record_type, [])
            if isinstance(values, list):
                for address in values:
                    _add_claim(claims, target, "resolves_to", str(address), dns_source)

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
