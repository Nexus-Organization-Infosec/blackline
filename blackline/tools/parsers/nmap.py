"""Parse Nmap output."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class NmapPort:
    """One parsed port entry from nmap output."""

    port: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""


@dataclass(frozen=True, slots=True)
class NmapParsedResult:
    """Structured view of a small nmap scan."""

    target: str = ""
    host_status: str = ""
    ports: tuple[NmapPort, ...] = ()
    device_type: str = ""
    operating_system: str = ""
    kernel: str = ""
    cpe: str = ""
    distance: str = ""
    raw_output: str = ""
    warnings: tuple[str, ...] = ()


def parse_nmap_output(output: str) -> NmapParsedResult:
    """Parse standard nmap stdout into a structured result."""
    target = ""
    host_status = ""
    ports: list[NmapPort] = []
    warnings: list[str] = []
    system = {"device_type": "", "operating_system": "", "kernel": "", "cpe": "", "distance": ""}

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

        if stripped.startswith("Device type: "):
            system["device_type"] = stripped.removeprefix("Device type: ").strip()
            continue
        if stripped.startswith("Running: "):
            system["operating_system"] = stripped.removeprefix("Running: ").strip()
            continue
        if stripped.startswith("OS details: "):
            details = stripped.removeprefix("OS details: ").strip()
            system["operating_system"] = details
            if "(" in details and ")" in details:
                possible_kernel = details.rsplit("(", 1)[1].removesuffix(")").strip()
                if possible_kernel.startswith("Darwin"):
                    system["kernel"] = possible_kernel
                    system["operating_system"] = details.rsplit("(", 1)[0].strip()
            continue
        if stripped.startswith("OS CPE: "):
            system["cpe"] = stripped.removeprefix("OS CPE: ").strip()
            continue
        if stripped.startswith("Network Distance: "):
            system["distance"] = stripped.removeprefix("Network Distance: ").strip()
            continue

        port = _parse_port_line(stripped)
        if port is not None:
            ports.append(port)

    return NmapParsedResult(
        target=target,
        host_status=host_status,
        ports=tuple(ports),
        device_type=system["device_type"],
        operating_system=system["operating_system"],
        kernel=system["kernel"],
        cpe=system["cpe"],
        distance=system["distance"],
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
    version = " ".join(columns[3:]) if len(columns) >= 4 else ""
    return NmapPort(port=int(port_value), protocol=protocol, state=state, service=service, version=version)
