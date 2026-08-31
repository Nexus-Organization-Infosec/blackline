"""DNS resolver tool wrapper."""

from __future__ import annotations

from dataclasses import dataclass, field
import socket
from typing import Callable, Sequence

from blackline.utils.exec import CommandResult

DnsProvider = Callable[[str, Sequence[str]], dict[str, list[str]]]
DEFAULT_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV")


@dataclass(frozen=True, slots=True)
class DnsLookupResult:
    """Structured DNS lookup result."""

    ok: bool
    host: str
    records: dict[str, list[str]] = field(default_factory=dict)
    resolved_ips: list[str] = field(default_factory=list)
    provider: str = ""
    outcome: str = ""
    raw_output: str = ""
    error: str = ""
    elapsed_seconds: float = 0.0


def resolve_dns(
    host: str,
    *,
    provider: DnsProvider | None = None,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    record_types: Sequence[str] = DEFAULT_RECORD_TYPES,
    timeout_seconds: float | None = None,
) -> DnsLookupResult:
    """Resolve structured DNS records for one host."""
    host = host.strip()
    if not host:
        return DnsLookupResult(ok=False, host=host, outcome="invalid", error="missing dns host")

    if provider is not None:
        records = _normalize_records(provider(host, record_types), record_types)
        return _result_from_records(host, records, provider_name="custom")

    result = _resolve_with_dnspython(host, record_types, timeout_seconds=timeout_seconds)
    if result is not None:
        return result

    return _resolve_with_socket(host, record_types)


def _resolve_with_dnspython(
    host: str,
    record_types: Sequence[str],
    *,
    timeout_seconds: float | None,
) -> DnsLookupResult | None:
    """Resolve standard records with explicit DNS outcomes when dnspython exists."""
    try:
        import dns.resolver  # type: ignore[import-not-found]
    except ImportError:
        return None

    resolver = dns.resolver.Resolver(configure=True)
    if timeout_seconds is not None and timeout_seconds > 0:
        resolver.timeout = timeout_seconds
        resolver.lifetime = timeout_seconds

    records: dict[str, list[str]] = {}
    failures: list[str] = []
    saw_timeout = False
    saw_nameserver_error = False
    saw_nxdomain = False
    for record_type in record_types:
        try:
            answers = resolver.resolve(host, record_type)
        except dns.resolver.NXDOMAIN:
            saw_nxdomain = True
            records[record_type] = []
            continue
        except dns.resolver.NoAnswer:
            records[record_type] = []
            continue
        except dns.resolver.LifetimeTimeout:
            saw_timeout = True
            records[record_type] = []
            continue
        except dns.resolver.NoNameservers as exc:
            saw_nameserver_error = True
            failures.append(str(exc))
            records[record_type] = []
            continue
        except Exception as exc:  # pragma: no cover - defensive third-party boundary.
            failures.append(str(exc))
            records[record_type] = []
            continue
        records[record_type] = [str(answer).rstrip(".") for answer in answers]
    records = _normalize_records(records, record_types)
    if any(records.values()):
        outcome = "answer" if not failures and not saw_timeout and not saw_nameserver_error else "partial"
        return DnsLookupResult(
            ok=True,
            host=host,
            records=records,
            resolved_ips=_resolved_ips(records),
            provider="dnspython",
            outcome=outcome,
            error="; ".join(failures),
        )
    if saw_nxdomain:
        return DnsLookupResult(
            ok=False,
            host=host,
            records=records,
            provider="dnspython",
            outcome="nxdomain",
            error=f"dns name does not exist: {host}",
        )
    if saw_timeout:
        return DnsLookupResult(
            ok=False,
            host=host,
            records=records,
            provider="dnspython",
            outcome="timeout",
            error=f"dns lookup timed out for {host}",
        )
    if saw_nameserver_error or failures:
        return DnsLookupResult(
            ok=False,
            host=host,
            records=records,
            provider="dnspython",
            outcome="resolver_error",
            error="; ".join(failures) or f"dns resolver failed for {host}",
        )
    return DnsLookupResult(
        ok=False,
        host=host,
        records=records,
        provider="dnspython",
        outcome="no_data",
        error=f"no requested DNS records for {host}",
    )


def _resolve_with_socket(host: str, record_types: Sequence[str]) -> DnsLookupResult:
    records = {record_type: [] for record_type in record_types}
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return DnsLookupResult(
            ok=False,
            host=host,
            records=records,
            provider="socket",
            outcome="resolver_error",
            error=str(exc),
        )

    ipv4: list[str] = []
    ipv6: list[str] = []
    for info in infos:
        family = info[0]
        address = info[4][0]
        if family == socket.AF_INET and address not in ipv4:
            ipv4.append(address)
        elif family == socket.AF_INET6 and address not in ipv6:
            ipv6.append(address)

    records["A"] = ipv4 if "A" in records else []
    records["AAAA"] = ipv6 if "AAAA" in records else []
    return DnsLookupResult(
        ok=bool(ipv4 or ipv6),
        host=host,
        records=records,
        resolved_ips=[*ipv4, *ipv6],
        provider="socket",
        outcome="answer" if (ipv4 or ipv6) else "no_data",
        error="" if (ipv4 or ipv6) else f"dns lookup failed for {host}",
    )


def _result_from_records(host: str, records: dict[str, list[str]], *, provider_name: str) -> DnsLookupResult:
    return DnsLookupResult(
        ok=any(records.values()),
        host=host,
        records=records,
        resolved_ips=_resolved_ips(records),
        provider=provider_name,
        outcome="answer" if any(records.values()) else "no_data",
        error="" if any(records.values()) else f"dns lookup failed for {host}",
    )


def _normalize_records(records: dict[str, list[str]], record_types: Sequence[str]) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for record_type in record_types:
        values = records.get(record_type, [])
        if not isinstance(values, list):
            values = [str(values)]
        normalized[record_type] = [str(value).strip().rstrip(".") for value in values if str(value).strip()]
    return normalized


def _resolved_ips(records: dict[str, list[str]]) -> list[str]:
    resolved: list[str] = []
    for key in ("A", "AAAA"):
        for value in records.get(key, []):
            if value not in resolved:
                resolved.append(value)
    return resolved
