"""IP intelligence tool wrapper."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
import tempfile
from pathlib import Path
from shutil import which
from typing import Callable

from blackline.config.tool_loader import get_tool_config
from blackline.tools.parsers.yougotmapped import (
    YouGotMappedParsedResult,
    parse_yougotmapped_json_file,
    parse_yougotmapped_stdout,
)
from blackline.utils.exec import run_command

IpIntelProvider = Callable[..., dict[str, object]]


@dataclass(frozen=True, slots=True)
class IpIntelResult:
    """Structured IP intelligence result."""

    ok: bool
    target: str
    lookup_ip: str
    asn: str = ""
    org: str = ""
    location: str = ""
    latency: float | None = None
    vpn_likely: bool | None = None
    confidence: str = ""
    jitter: float | None = None
    bandwidth: float | None = None
    domain: str = ""
    mss: int | None = None
    trace: list[str] = field(default_factory=list)
    provider: str = ""
    raw: dict[str, object] = field(default_factory=dict)
    error: str = ""


def resolve_ipintel(
    target: str,
    *,
    lookup_ip: str = "",
    deep: bool = False,
    provider: IpIntelProvider | None = None,
    timeout_seconds: float | None = None,
) -> IpIntelResult:
    """Resolve curated IP intelligence for one target."""
    target = target.strip()
    lookup_ip = (lookup_ip or target).strip()
    if not lookup_ip:
        return IpIntelResult(ok=False, target=target, lookup_ip=lookup_ip, error="missing ipintel target")

    if provider is not None:
        try:
            raw = provider(lookup_ip, deep, timeout_seconds)  # type: ignore[misc]
        except TypeError:
            raw = provider(lookup_ip, deep)
        return _result_from_mapping(target, lookup_ip, raw)

    execution = _run_yougotmapped(lookup_ip, deep=deep, timeout_seconds=timeout_seconds)
    if execution is not None:
        if execution.ok:
            return _result_from_parsed(target, execution)
        if _is_private_ip(lookup_ip):
            private_address = ipaddress.ip_address(lookup_ip)
            return _local_ipintel(target, private_address, deep=deep)
        return IpIntelResult(
            ok=False,
            target=target,
            lookup_ip=execution.lookup_ip or lookup_ip,
            provider="yougotmapped",
            error=execution.error or "yougotmapped failed",
            raw=execution.raw,
        )

    if _is_private_ip(lookup_ip):
        return _local_ipintel(target, ipaddress.ip_address(lookup_ip), deep=deep)

    return IpIntelResult(
        ok=False,
        target=target,
        lookup_ip=lookup_ip,
        provider="yougotmapped",
        error="yougotmapped binary not found",
    )


def _local_ipintel(target: str, address: ipaddress._BaseAddress, *, deep: bool) -> IpIntelResult:
    if address.is_private:
        trace = [str(address)] if deep else []
        return IpIntelResult(
            ok=True,
            target=target,
            lookup_ip=str(address),
            asn="AS-PRIVATE",
            org="Private Network",
            location="private / internal",
            latency=1.0,
            vpn_likely=False,
            confidence="low",
            jitter=0.1 if deep else None,
            bandwidth=1000.0 if deep else None,
            domain="",
            mss=1460 if deep else None,
            trace=trace,
            provider="local",
            raw={"private": True, "note": "Private / non-routable address"},
        )

    return IpIntelResult(
        ok=False,
        target=target,
        lookup_ip=str(address),
        provider="local",
        error="ipintel provider unavailable for public IP enrichment",
    )


def _result_from_mapping(target: str, lookup_ip: str, raw: dict[str, object]) -> IpIntelResult:
    trace = raw.get("trace", [])
    if not isinstance(trace, list):
        trace = []
    return IpIntelResult(
        ok=bool(raw.get("ok", True)),
        target=target,
        lookup_ip=lookup_ip,
        asn=str(raw.get("asn", "")),
        org=str(raw.get("org", "")),
        location=str(raw.get("location", "")),
        latency=_float_or_none(raw.get("latency")),
        vpn_likely=_bool_or_none(raw.get("vpn_likely")),
        confidence=str(raw.get("confidence", "")),
        jitter=_float_or_none(raw.get("jitter")),
        bandwidth=_float_or_none(raw.get("bandwidth")),
        domain=str(raw.get("domain", "")),
        mss=_int_or_none(raw.get("mss")),
        trace=[str(item) for item in trace],
        provider=str(raw.get("provider", "custom")),
        raw=raw,
        error=str(raw.get("error", "")),
    )


def _result_from_parsed(target: str, parsed: YouGotMappedParsedResult) -> IpIntelResult:
    return IpIntelResult(
        ok=parsed.ok,
        target=target,
        lookup_ip=parsed.lookup_ip,
        asn=parsed.asn,
        org=parsed.org,
        location=parsed.location,
        latency=parsed.latency,
        vpn_likely=parsed.vpn_likely,
        confidence=parsed.confidence,
        jitter=parsed.jitter,
        bandwidth=parsed.bandwidth,
        domain=parsed.domain,
        mss=parsed.mss,
        trace=list(parsed.trace),
        provider="yougotmapped",
        raw=parsed.raw,
        error=parsed.error,
    )


def build_yougotmapped_command(
    target: str,
    *,
    deep: bool = False,
    output_path: str | Path | None = None,
    config: dict | None = None,
) -> tuple[str, ...]:
    """Build the `yougotmapped` command from configuration."""
    config = config or get_tool_config("yougotmapped")
    defaults = _mapping(config.get("defaults"))
    binary = str(config.get("binary") or "yougotmapped")
    command = [binary, "-i", target]

    flags = defaults.get("deep_flags" if deep else "default_flags", [])
    if isinstance(flags, list):
        command.extend(str(flag) for flag in flags)
    if bool(defaults.get("no_map", True)):
        command.append("--no-map")
    if output_path is not None:
        command.extend(["-o", str(output_path)])
    return tuple(command)


def _run_yougotmapped(target: str, *, deep: bool, timeout_seconds: float | None) -> YouGotMappedParsedResult | None:
    config = get_tool_config("yougotmapped")
    binary = str(config.get("binary") or "yougotmapped")
    if which(binary) is None:
        return None

    with tempfile.TemporaryDirectory(prefix="blackline-ygm-") as directory:
        output_path = Path(directory) / "yougotmapped.json"
        command = build_yougotmapped_command(target, deep=deep, output_path=output_path, config=config)
        result = run_command(command, timeout=timeout_seconds)
        if output_path.exists():
            try:
                parsed = parse_yougotmapped_json_file(output_path)
            except (OSError, ValueError, json.JSONDecodeError):  # type: ignore[name-defined]
                parsed = parse_yougotmapped_stdout(result.stdout)
        else:
            parsed = parse_yougotmapped_stdout(result.stdout)

        if parsed.ok:
            return parsed

        stderr = " ".join(result.stderr.split())
        if stderr and not parsed.error:
            return YouGotMappedParsedResult(ok=False, lookup_ip=parsed.lookup_ip, error=stderr)
        if result.returncode == 124 and not parsed.error:
            return YouGotMappedParsedResult(
                ok=False,
                lookup_ip=parsed.lookup_ip or target,
                error=f"yougotmapped timed out after {timeout_seconds:.1f} seconds" if timeout_seconds else "yougotmapped timed out",
            )
        return parsed


def _mapping(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


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
        if lowered in {"true", "yes", "1", "likely"}:
            return True
        if lowered in {"false", "no", "0", "unlikely"}:
            return False
    return None
