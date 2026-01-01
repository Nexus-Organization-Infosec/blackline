# blackline/backend/recon/nmap_parser.py
def parse_nmap_output(stdout: str) -> dict:
    open_ports = []
    services = {}

    lines = stdout.splitlines()
    parsing = False

    for line in lines:
        if line.startswith("PORT"):
            parsing = True
            continue

        if not parsing or not line.strip():
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        port_proto, state, service = parts[:3]
        if state != "open":
            continue

        try:
            port = int(port_proto.split("/")[0])
        except ValueError:
            continue

        open_ports.append(port)
        services[port] = service

    return {
        "open_ports": open_ports,
        "services": services
    }
