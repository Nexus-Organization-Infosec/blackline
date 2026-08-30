"""Parsers for yougotmapped output."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path


@dataclass(frozen=True, slots=True)
class YouGotMappedParsedResult:
    """Normalized subset of one yougotmapped execution."""

    ok: bool
    lookup_ip: str
    asn: str = ""
    org: str = ""
    domain: str = ""
    location: str = ""
    latency: float | None = None
    vpn_likely: bool | None = None
    confidence: str = ""
    jitter: float | None = None
    bandwidth: float | None = None
    mss: int | None = None
    trace: list[str] = field(default_factory=list)
    raw: dict[str, object] = field(default_factory=dict)
    error: str = ""


def parse_yougotmapped_json_file(path: str | Path) -> YouGotMappedParsedResult:
    """Parse one yougotmapped JSON export file."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_yougotmapped_json(raw)


def parse_yougotmapped_json(raw: object) -> YouGotMappedParsedResult:
    """Parse normalized data from one yougotmapped JSON payload."""
    if not isinstance(raw, list) or not raw:
        return YouGotMappedParsedResult(ok=False, lookup_ip="", error="yougotmapped returned no results")

    entry = raw[0]
    if not isinstance(entry, dict):
        return YouGotMappedParsedResult(ok=False, lookup_ip="", error="yougotmapped returned invalid results")

    private = bool(entry.get("private", False))
    raw_geo = entry.get("raw", {})
    if not isinstance(raw_geo, dict):
        raw_geo = {}
    connection = raw_geo.get("connection", {})
    if not isinstance(connection, dict):
        connection = {}

    lookup_ip = str(entry.get("ip", "")).strip()
    domain = str(connection.get("domain") or "").strip()
    org = str(connection.get("org") or entry.get("org") or connection.get("isp") or "").strip()
    asn_value = connection.get("asn")
    asn = f"AS{asn_value}" if asn_value not in {None, ""} else ""
    location = _location_text(entry, raw_geo, private=private)

    ping = entry.get("ping", {})
    if not isinstance(ping, dict):
        ping = {}
    jitter = entry.get("jitter", {})
    if not isinstance(jitter, dict):
        jitter = {}
    bandwidth = entry.get("bandwidth", {})
    if not isinstance(bandwidth, dict):
        bandwidth = {}
    anonymity = entry.get("anonymity", {})
    if not isinstance(anonymity, dict):
        anonymity = {}
    mss = entry.get("mss", {})
    if not isinstance(mss, dict):
        mss = {}
    traceroute = entry.get("traceroute", {})
    if not isinstance(traceroute, dict):
        traceroute = {}

    if private:
        return YouGotMappedParsedResult(
            ok=True,
            lookup_ip=lookup_ip,
            asn="AS-PRIVATE",
            org=org or "Private Network",
            domain=domain,
            location=location or "private / internal",
            latency=_ping_latency_ms(ping),
            vpn_likely=_bool_or_none(anonymity.get("vpn")),
            confidence=str(anonymity.get("confidence", "low") or "low"),
            jitter=_float_or_none(jitter.get("jitter_ms")),
            bandwidth=_float_or_none(bandwidth.get("estimated_mbps")),
            mss=_int_or_none(mss.get("mss")),
            trace=_trace_lines(traceroute),
            raw=entry,
        )

    if not lookup_ip:
        return YouGotMappedParsedResult(ok=False, lookup_ip="", raw=entry, error="yougotmapped returned no lookup IP")

    return YouGotMappedParsedResult(
        ok=True,
        lookup_ip=lookup_ip,
        asn=asn,
        org=org,
        domain=domain,
        location=location,
        latency=_ping_latency_ms(ping),
        vpn_likely=_bool_or_none(anonymity.get("vpn")),
        confidence=str(anonymity.get("confidence", "")).strip(),
        jitter=_float_or_none(jitter.get("jitter_ms")),
        bandwidth=_float_or_none(bandwidth.get("estimated_mbps")),
        mss=_int_or_none(mss.get("mss")),
        trace=_trace_lines(traceroute),
        raw=entry,
    )


def parse_yougotmapped_stdout(stdout: str) -> YouGotMappedParsedResult:
    """Parse minimal failure information from human-readable stdout."""
    lookup_ip = ""
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Target:"):
            lookup_ip = stripped.partition(":")[2].strip()
        if "Failed to retrieve geolocation data." in stripped:
            return YouGotMappedParsedResult(
                ok=False,
                lookup_ip=lookup_ip,
                error="failed to retrieve geolocation data",
            )
    return YouGotMappedParsedResult(
        ok=False,
        lookup_ip=lookup_ip,
        error="yougotmapped produced no machine-readable output",
    )


def _location_text(entry: dict[str, object], raw_geo: dict[str, object], *, private: bool) -> str:
    if private:
        return "private / internal"
    country = str(raw_geo.get("country_code") or entry.get("country") or "").strip()
    region = str(raw_geo.get("region_code") or entry.get("region") or "").strip()
    city = str(raw_geo.get("city") or entry.get("city") or "").strip()
    return " / ".join(part for part in (country, region, city) if part)


def _ping_latency_ms(ping: dict[str, object]) -> float | None:
    rtt = ping.get("rtt_ms", {})
    if not isinstance(rtt, dict):
        return None
    return _float_or_none(rtt.get("avg") if "avg" in rtt else rtt.get("median"))


def _trace_lines(traceroute: dict[str, object]) -> list[str]:
    hops = traceroute.get("hops", [])
    if not isinstance(hops, list):
        return []

    lines: list[str] = []
    for hop in hops:
        if not isinstance(hop, dict):
            continue
        hop_no = _int_or_none(hop.get("hop"))
        ip = str(hop.get("ip", "")).strip()
        if hop_no is None or not ip:
            continue
        visibility = "PRIVATE" if bool(hop.get("private", False)) else "PUBLIC"
        rtts = hop.get("rtt_ms")
        rtt_text = "*"
        if isinstance(rtts, list) and rtts:
            numeric = [float(value) for value in rtts if isinstance(value, (int, float))]
            if numeric:
                rtt_text = f"{min(numeric):.1f} ms"
        lines.append(f"[{hop_no:>2}] {ip:<15} {visibility:<7} {rtt_text}")
    return lines


def _float_or_none(value: object) -> float | None:
    try:
        if value in {None, ""}:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _int_or_none(value: object) -> int | None:
    try:
        if value in {None, ""}:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _bool_or_none(value: object) -> bool | None:
    if value in {None, ""}:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return None
