"""Network command."""

from __future__ import annotations

import json
import socket
import subprocess
import urllib.request
from dataclasses import dataclass

from blackline.cli.ui.display import section, write_line


@dataclass(frozen=True, slots=True)
class LocalNetworkInfo:
    ip: str = "unknown"
    gateway: str = "unknown"
    interface: str = "unknown"


@dataclass(frozen=True, slots=True)
class ExternalNetworkInfo:
    ip: str = "unknown"
    asn: str = "unknown"
    location: str = "unknown"


def handle_network(*, use_color: bool | None = None) -> None:
    """Render local and external network information."""
    local = get_local_network_info()
    external = get_external_network_info()

    write_line("[network]", use_color=use_color)
    write_line(use_color=use_color)
    section(
        "local",
        [
            ("ip", local.ip),
            ("gateway", local.gateway),
            ("interface", local.interface),
        ],
        use_color=use_color,
    )
    write_line(use_color=use_color)
    section(
        "external",
        [
            ("ip", external.ip),
            ("asn", external.asn),
            ("location", external.location),
        ],
        use_color=use_color,
    )


def get_local_network_info() -> LocalNetworkInfo:
    """Best-effort local IP/gateway/interface discovery."""
    ip = _local_ip()
    gateway, interface = _default_route()
    return LocalNetworkInfo(ip=ip or "unknown", gateway=gateway or "unknown", interface=interface or "unknown")


def get_external_network_info(timeout: float = 3.0) -> ExternalNetworkInfo:
    """Best-effort external IP metadata discovery."""
    try:
        request = urllib.request.Request("https://ipapi.co/json/", headers={"User-Agent": "blackline/0.1"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
    except Exception:
        return ExternalNetworkInfo()

    ip = str(data.get("ip") or "unknown")
    asn = _external_asn(data)
    location = _external_location(data)
    return ExternalNetworkInfo(ip=ip, asn=asn, location=location)


def _local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        sock.close()


def _default_route() -> tuple[str, str]:
    commands = [
        ["ip", "route", "show", "default"],
        ["route", "-n", "get", "default"],
    ]

    for command in commands:
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=2, check=False)
        except Exception:
            continue

        output = completed.stdout or ""
        if command[0] == "ip":
            gateway = _token_after(output.split(), "via")
            interface = _token_after(output.split(), "dev")
            if gateway or interface:
                return gateway, interface
        else:
            gateway = _line_value(output, "gateway:")
            interface = _line_value(output, "interface:")
            if gateway or interface:
                return gateway, interface

    return "", ""


def _token_after(tokens: list[str], marker: str) -> str:
    try:
        return tokens[tokens.index(marker) + 1]
    except (ValueError, IndexError):
        return ""


def _line_value(output: str, prefix: str) -> str:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.split(":", 1)[1].strip()
    return ""


def _external_asn(data: dict) -> str:
    asn = str(data.get("asn") or "").strip()
    org = str(data.get("org") or "").strip()
    if asn and org:
        return f"{asn} {org}"
    return asn or org or "unknown"


def _external_location(data: dict) -> str:
    country = str(data.get("country_code") or data.get("country") or "").strip()
    city = str(data.get("city") or "").strip()
    if country and city:
        return f"{country}, {city}"
    return country or city or "unknown"
