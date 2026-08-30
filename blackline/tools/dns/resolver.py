"""DNS resolver tool wrapper."""

from __future__ import annotations

from dataclasses import dataclass, field
import socket
from shutil import which
from typing import Callable, Sequence

from blackline.utils.exec import CommandResult, run_command

DnsProvider = Callable[[str, Sequence[str]], dict[str, list[str]]]


@dataclass(frozen=True, slots=True)
class DnsLookupResult:
    """Structured DNS lookup result."""

    ok: bool
    host: str
    records: dict[str, list[str]] = field(default_factory=dict)
    resolved_ips: list[str] = field(default_factory=list)
    provider: str = ""
    raw_output: str = ""
    error: str = ""
    elapsed_seconds: float = 0.0


def resolve_dns(
    host: str,
    *,
    provider: DnsProvider | None = None,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
    record_types: Sequence[str] = ("A", "AAAA", "MX", "NS"),
    timeout_seconds: float | None = None,
) -> DnsLookupResult:
    """Resolve structured DNS records for one host."""
    host = host.strip()
    if not host:
        return DnsLookupResult(ok=False, host=host, error="missing dns host")

    if provider is not None:
        records = _normalize_records(provider(host, record_types), record_types)
        return _result_from_records(host, records, provider_name="custom")

    records = _resolve_with_dnspython(host, record_types)
    if records is not None:
        return _result_from_records(host, records, provider_name="dnspython")

    if which("dig") is not None:
        executor = command_executor or (lambda args: run_command(args, timeout=timeout_seconds if timeout_seconds is not None else 15.0))
        return _resolve_with_dig(host, record_types, executor=executor)

    return _resolve_with_socket(host, record_types)


def _resolve_with_dnspython(host: str, record_types: Sequence[str]) -> dict[str, list[str]] | None:
    try:
        import dns.resolver  # type: ignore[import-not-found]
    except ImportError:
        return None

    records: dict[str, list[str]] = {}
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(host, record_type)
        except Exception:
            records[record_type] = []
            continue
        records[record_type] = [str(answer).rstrip(".") for answer in answers]
    return _normalize_records(records, record_types)


def _resolve_with_dig(
    host: str,
    record_types: Sequence[str],
    *,
    executor: Callable[[tuple[str, ...]], CommandResult],
) -> DnsLookupResult:
    records: dict[str, list[str]] = {}
    raw_chunks: list[str] = []
    max_elapsed = 0.0
    for record_type in record_types:
        result = executor(("dig", "+short", host, record_type))
        max_elapsed = max(max_elapsed, result.elapsed_seconds)
        if result.stdout:
            raw_chunks.append(result.stdout.strip())
        if not result.ok and result.returncode != 0:
            records[record_type] = []
            continue
        values = [line.strip().rstrip(".") for line in result.stdout.splitlines() if line.strip()]
        records[record_type] = values

    records = _normalize_records(records, record_types)
    if any(records.values()):
        return DnsLookupResult(
            ok=True,
            host=host,
            records=records,
            resolved_ips=_resolved_ips(records),
            provider="dig",
            raw_output="\n".join(chunk for chunk in raw_chunks if chunk),
            elapsed_seconds=max_elapsed,
        )
    return DnsLookupResult(
        ok=False,
        host=host,
        records=records,
        resolved_ips=[],
        provider="dig",
        error=f"dns lookup failed for {host}",
        raw_output="\n".join(chunk for chunk in raw_chunks if chunk),
        elapsed_seconds=max_elapsed,
    )


def _resolve_with_socket(host: str, record_types: Sequence[str]) -> DnsLookupResult:
    records = {record_type: [] for record_type in record_types}
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return DnsLookupResult(ok=False, host=host, records=records, error=str(exc), provider="socket")

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
        error="" if (ipv4 or ipv6) else f"dns lookup failed for {host}",
    )


def _result_from_records(host: str, records: dict[str, list[str]], *, provider_name: str) -> DnsLookupResult:
    return DnsLookupResult(
        ok=any(records.values()),
        host=host,
        records=records,
        resolved_ips=_resolved_ips(records),
        provider=provider_name,
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
