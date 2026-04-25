"""Parse Nmap output."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class NmapPort:
    """One parsed port entry from nmap output."""

    port: int
    protocol: str
    state: str
    service: str = ""


@dataclass(frozen=True, slots=True)
class NmapParsedResult:
    """Structured view of a small nmap scan."""

    target: str = ""
    host_status: str = ""
    ports: tuple[NmapPort, ...] = ()
    raw_output: str = ""
    warnings: tuple[str, ...] = ()


def parse_nmap_output(output: str) -> NmapParsedResult:
    """Parse standard nmap stdout into a structured result."""
    target = ""
    host_status = ""
    ports: list[NmapPort] = []
    warnings: list[str] = []

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("Nmap scan report for "):
            target = stripped.removeprefix("Nmap scan report for ").strip()
            continue

        if stripped.startswith("Host is up"):
            host_status = "up"
            continue

        if stripped.startswith("Host is down"):
            host_status = "down"
            continue

        if stripped.startswith(("Warning:", "Note:")):
            warnings.append(stripped)
            continue

        port = _parse_port_line(stripped)
        if port is not None:
            ports.append(port)

    return NmapParsedResult(
        target=target,
        host_status=host_status,
        ports=tuple(ports),
        raw_output=output,
        warnings=tuple(warnings),
    )


def _parse_port_line(line: str) -> NmapPort | None:
    columns = line.split()
    if len(columns) < 2 or "/" not in columns[0]:
        return None

    port_value, protocol = columns[0].split("/", 1)
    if not port_value.isdigit():
        return None

    state = columns[1]
    service = columns[2] if len(columns) >= 3 else ""
    return NmapPort(port=int(port_value), protocol=protocol, state=state, service=service)
