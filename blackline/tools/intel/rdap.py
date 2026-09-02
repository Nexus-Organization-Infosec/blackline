"""Structured RDAP registration and network ownership lookups."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

RdapFetcher = Callable[[str, float], dict[str, object]]
RDAP_BASE_URL = "https://rdap.org"


@dataclass(frozen=True, slots=True)
class RdapResult:
    """Normalized RDAP facts for a domain and/or network address."""

    ok: bool
    domain: str = ""
    registrar: str = ""
    created: str = ""
    expires: str = ""
    status: tuple[str, ...] = field(default_factory=tuple)
    address: str = ""
    network: str = ""
    organization: str = ""
    asn: str = ""
    provider: str = "rdap.org"
    warnings: tuple[str, ...] = field(default_factory=tuple)
    raw: dict[str, object] = field(default_factory=dict)
    error: str = ""
    elapsed_seconds: float = 0.0


def resolve_rdap(
    *,
    domain: str = "",
    address: str = "",
    timeout_seconds: float = 10.0,
    fetcher: RdapFetcher | None = None,
) -> RdapResult:
    """Look up domain registration and IP ownership through public RDAP."""
    domain = domain.strip().lower()
    address = address.strip()
    if not domain and not address:
        return RdapResult(False, error="missing RDAP domain or address")

    started = time.perf_counter()
    raw: dict[str, object] = {}
    warnings: list[str] = []
    not_found_count = 0
    attempted_count = int(bool(domain)) + int(bool(address))
    domain_data: dict[str, object] = {}
    address_data: dict[str, object] = {}

    if domain:
        domain_response = _fetch_rdap(f"{RDAP_BASE_URL}/domain/{quote(domain, safe='')}", timeout_seconds, fetcher)
        if domain_response["ok"]:
            domain_data = domain_response["data"]
            raw["domain"] = domain_data
        elif domain_response["not_found"]:
            not_found_count += 1
        else:
            warnings.append(str(domain_response["error"]))

    if address:
        address_response = _fetch_rdap(f"{RDAP_BASE_URL}/ip/{quote(address, safe='')}", timeout_seconds, fetcher)
        if address_response["ok"]:
            address_data = address_response["data"]
            raw["network"] = address_data
        elif address_response["not_found"]:
            not_found_count += 1
        else:
            warnings.append(str(address_response["error"]))

    registration = _registration_fields(domain_data, fallback_domain=domain)
    ownership = _ownership_fields(address_data, fallback_address=address)
    completed_lookup = bool(domain_data or address_data)
    successful_absence = attempted_count > 0 and not_found_count == attempted_count
    return RdapResult(
        ok=completed_lookup or successful_absence,
        domain=registration["domain"],
        registrar=registration["registrar"],
        created=registration["created"],
        expires=registration["expires"],
        status=registration["status"],
        address=ownership["address"],
        network=ownership["network"],
        organization=ownership["organization"],
        asn=ownership["asn"],
        warnings=tuple(warnings),
        raw=raw,
        error="" if completed_lookup or successful_absence else (warnings[0] if warnings else "RDAP lookup failed"),
        elapsed_seconds=time.perf_counter() - started,
    )


def _fetch_rdap(url: str, timeout_seconds: float, fetcher: RdapFetcher | None) -> dict[str, object]:
    if fetcher is not None:
        response = fetcher(url, timeout_seconds)
        status = int(response.get("status_code", 200)) if response.get("status_code") is not None else 0
        data = response.get("data", {})
        if status == 404:
            return {"ok": False, "not_found": True, "data": {}, "error": ""}
        return {"ok": 200 <= status < 300 and isinstance(data, dict), "not_found": False, "data": data if isinstance(data, dict) else {}, "error": str(response.get("error", "RDAP request failed"))}
    try:
        request = Request(url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": "blackline/0.1"})
        with urlopen(request, timeout=timeout_seconds) as response:
            data = json.loads(response.read(1_000_000).decode("utf-8", errors="replace"))
            return {"ok": isinstance(data, dict), "not_found": False, "data": data if isinstance(data, dict) else {}, "error": ""}
    except HTTPError as exc:
        if exc.code == 404:
            return {"ok": False, "not_found": True, "data": {}, "error": ""}
        return {"ok": False, "not_found": False, "data": {}, "error": f"RDAP HTTP {exc.code}"}
    except (URLError, OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "not_found": False, "data": {}, "error": str(exc)}


def _registration_fields(data: dict[str, object], *, fallback_domain: str) -> dict[str, object]:
    events = _events(data)
    return {
        "domain": str(data.get("ldhName") or data.get("unicodeName") or fallback_domain),
        "registrar": _entity_name(data.get("entities"), "registrar"),
        "created": events.get("registration", ""),
        "expires": events.get("expiration", ""),
        "status": tuple(str(value) for value in data.get("status", []) if str(value)) if isinstance(data.get("status"), list) else (),
    }


def _ownership_fields(data: dict[str, object], *, fallback_address: str) -> dict[str, str]:
    start = str(data.get("startAddress") or "")
    end = str(data.get("endAddress") or "")
    network = str(data.get("name") or "")
    if start and end:
        network = f"{network} ({start} – {end})".strip()
    return {
        "address": fallback_address,
        "network": network,
        "organization": _entity_name(data.get("entities"), "registrant") or _entity_name(data.get("entities"), "technical"),
        "asn": _asn(data),
    }


def _events(data: dict[str, object]) -> dict[str, str]:
    values: dict[str, str] = {}
    events = data.get("events", [])
    if not isinstance(events, list):
        return values
    for event in events:
        if isinstance(event, dict) and event.get("eventAction") and event.get("eventDate"):
            values[str(event["eventAction"]).lower()] = str(event["eventDate"])
    return values


def _entity_name(entities: object, role: str) -> str:
    if not isinstance(entities, list):
        return ""
    for entity in entities:
        if not isinstance(entity, dict) or role not in entity.get("roles", []):
            continue
        vcard = entity.get("vcardArray", [])
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] in {"fn", "org"}:
                    value = item[3]
                    return " ".join(str(part) for part in value) if isinstance(value, list) else str(value)
        return str(entity.get("handle") or "")
    return ""


def _asn(data: dict[str, object]) -> str:
    values = data.get("arin_originas0_originautnums") or data.get("originAutnum") or data.get("autnum")
    if isinstance(values, list) and values:
        values = values[0]
    value = str(values or "").strip()
    if not value:
        return ""
    return value if value.upper().startswith("AS") else f"AS{value}"
