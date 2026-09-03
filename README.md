# Blackline

Blackline is a Python CLI framework for authorized security workflows. v0.1.0 focuses on reconnaissance, providing a structured recon workflow for target discovery, network intelligence, HTTP probing, and port and service enumeration.

> This is an active development build. Commands and output may change as the
> architecture evolves.

## Requirements

- Python 3.11 or newer
- `nmap` installed and available on your `PATH` for port scanning
- Optional: `yougotmapped` for richer IP intelligence

## Getting started

Create a virtual environment, install the package, and start the shell:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
blackline
```

## Recon

`recon` accepts an IP address, domain, or URL and builds an appropriate
pipeline for that target.

```bash
recon[target=example.com]
recon[target=203.0.113.10, ports=80,443]
recon[target=https://example.com/login, strategy=fast, probe=service]
```

Supported recon options are:

- `target` — required IP address, domain, or URL
- `ports` — ports or port ranges, such as `22,80,443` or `1-1024`
- `top_ports` — scan the top N common ports
- `strategy` — `surface`, `balanced`, `quiet`, `fast`, `deep`, or `udp`
- `speed` — `low`, `normal`, `high`, or `aggressive`
- `probe` — `surface`, `service`, `script`, or `fingerprint`
- `transport` — `tcp` or `udp`

Profiles deliberately choose different work:

- `surface` performs DNS, ordinary web/TLS observations, fingerprinting, and RDAP—no port scan or network-intel lookup.
- `balanced` runs the complete standard evidence set.
- `deep` runs the complete set with deep network intelligence and the aggressive Nmap profile.

`quiet`, `fast`, and `udp` remain compatibility strategies; `fast` uses the surface evidence set.

Only scan systems you own or are explicitly authorized to test.

## Other current commands

```text
help                  Show available commands
network               Show network information
new <expression>      Create a job
jobs                  List jobs
enter <job-id>        Enter a job context
show [job-id]         Show job details
history               Show command history
version               Show the current version
exit                  Leave the job context or quit
```

## Project layout

```text
blackline/
  cli/       Command-line interface and output
  engine/    Expression parsing, planning, and execution
  core/      Domain pipelines and structured models
  tools/     DNS, HTTP, intelligence, and network adapters
  storage/   Jobs, history, and cache data
  config/    Tool and command configuration
tests/       Automated tests
docs/        Architecture and recon design notes
```

## Development

Run the test suite from the repository root:

```bash
pytest -q
```

The architecture direction and recon roadmap are documented in
[`docs/architecture.md`](https://github.com/Nexus-Organization-Infosec/blackline/blob/dev/v0.1.0/docs/architecture.md) and
[`docs/recon-design.md`](https://github.com/Nexus-Organization-Infosec/blackline/blob/dev/v0.1.0/docs/recon-design.md).
