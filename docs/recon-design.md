# Blackline Dev Note — `recon` Mega Toolchain

## Purpose

`recon` is the main reconnaissance orchestrator. It coordinates smaller recon
steps such as port scanning, DNS lookup, reverse DNS, HTTP probing, and later
subdomain discovery. It should feel like one clean user-facing command while
internally producing structured, report-ready job data.

`recon` is not one giant hardcoded tool. It is a pipeline runner.

```bash
recon[target=example.com, strategy=balanced, speed=normal, probe=surface]
```

or:

```bash
recon[target=10.0.0.1, strategy=balanced, speed=normal, probe=surface]
```

## Core Model

```text
user input
  -> detect target type
  -> create job
  -> choose recon pipeline
  -> run steps
  -> show native-feeling output
  -> store structured results
  -> summarize
```

Every `recon[...]` command creates a job automatically.

Manual job mode still exists:

```bash
new recon[target=10.0.0.1]
```

This creates and enters a job without immediately running unless the user calls
`run`.

## Determinism Rule

Given the same input and parameters, recon should produce logically consistent
results unless external conditions change.

Do not introduce randomness in:

- pipeline order
- module selection
- output structure

This matters for:

- debugging
- reports
- trust

## Idempotency Rule

Running the same recon command multiple times should:

- not corrupt previous jobs
- produce new jobs with independent results
- not overwrite existing data unless explicitly requested

## Target Type Detection

Before running, detect whether the target is:

```text
IP address
domain
URL
```

If the target is an IP, use IP recon mode:

```text
reverse_dns -> ipintel -> http_ip_probe -> http_vhost_probe -> port_scan
```

If the target is a domain, use domain recon mode:

```text
dns -> resolve IP -> ipintel -> http_probe -> subdomain/later -> port_scan
```

If the target is a URL, normalize it into:

```text
scheme
host
port if present
path if present
```

Then run HTTP-focused recon and optionally DNS and ports on the host.

## Recon Identity

```text
recon is not a scanner
recon is not a wrapper
recon is a structured intelligence pipeline
```

## Pipeline Consistency Rule

All recon steps must follow one naming standard:

```text
reverse_dns
dns
ipintel
http_probe
http_ip_probe
http_vhost_probe
port_scan
```

Avoid mixing naming styles.

Each step must:

- have a clear section header
- avoid redundant metadata
- feel native to the tool it represents

## IP Mode Behavior

If the user provides an IP address, run reverse DNS first.

Important rule:

```text
reverse DNS is a hint, not truth
```

Do not claim the IP belongs to the domain. Only store and report it as a PTR
or reverse DNS result.

Example output:

```bash
blackline ❯ recon[target=10.0.0.1, strategy=balanced, speed=normal, probe=surface]

[info] job #NFID created

[reverse_dns]
none

[ipintel]
asn       : AS15169 Google
location  : US / CA / Mountain View
latency   : ~19.8 ms

nmap -Pn -T3 -p 1-1024 10.0.0.1

Starting Nmap 7.99 ...
...
[result] 3 open, 3 filtered (3m 44.3s) -> #NFID
```

If reverse DNS exists:

```bash
[reverse_dns]
router.local

[http]
http://10.0.0.1       200
https://10.0.0.1      failed

[http:vhost]
http://router.local   200
```

HTTP probing should always try the IP directly:

```text
http://<ip>
https://<ip>
```

If reverse DNS returns names, optionally probe those too as virtual-host hints:

```text
http://<ptr-name>
https://<ptr-name>
```

Label these separately as `http:vhost` or `reverse_dns_http`, not as guaranteed
ownership.

## IP Intelligence Enrichment

`ipintel` is a supporting module used within recon to enrich IP or resolved
domain targets with external intelligence such as ASN, organization, location,
and network characteristics.

It is powered internally by the `yougotmapped` engine but exposed through a
curated and simplified interface.

Placement in pipeline:

### IP target

```text
reverse_dns
ipintel
http_ip_probe
http_vhost_probe
port_scan
```

### Domain target

```text
dns -> resolve IP -> ipintel -> http_probe -> port_scan
```

Purpose:

```text
ipintel provides context, not exposure
```

It answers:

```text
who owns this IP?
where is it located?
what kind of network is this?
```

It does not replace:

```text
port scanning
HTTP probing
```

Default behavior is lightweight:

```text
asn
organization
location
basic latency estimate
anonymity signal
```

Default output:

```bash
[ipintel]
asn       : AS15169 Google
location  : US / CA / Mountain View
latency   : ~19.8 ms

[anonymity]
vpn       : likely
confidence: high
```

When:

```bash
recon[target=..., strategy=deep]
```

`ipintel` expands to include advanced diagnostics:

```text
jitter
bandwidth estimate
traceroute
mss/mtu
```

Deep output example:

```bash
[ipintel]

network
───────
latency   : ~19.8 ms
jitter    : 5.9 ms
bandwidth : ~0.64 Mbps

[trace]
1  10.0.0.1
...
22 8.8.8.8
```

Data handling rules:

- always store full raw results internally
- only display summarized data in default output
- never assume ownership from reverse DNS or ASN

## Domain Mode Behavior

If target is a domain:

```text
dns lookup
http probe
port scan
subdomain later
```

Example:

```bash
blackline ❯ recon[target=example.com]

[dns]
A      93.184.216.34
AAAA   2606:2800:220:1:248:1893:25c8:1946
MX     none

[ipintel]
asn       : AS15133 Edgecast
location  : US / CA / Los Angeles
latency   : ~12.4 ms

[http]
https://example.com   200   Example Domain
http://example.com    301   -> https://example.com

[ports]
80/tcp    open    http
443/tcp   open    https

[result] recon complete (3 modules, 12.4s) -> #A12F
```

## Output Philosophy

Show what the user cares about.

Do not dump framework metadata during normal output.

Avoid:

```bash
target   :
host     :
elapsed  :
ports    :
```

Prefer native-feeling output:

```bash
nmap -Pn -T3 -p 1-1024 10.0.0.1

PORT    STATE     SERVICE
22/tcp  filtered  ssh
23/tcp  filtered  telnet
53/tcp  open      domain
80/tcp  open      http
111/tcp filtered  rpcbind
443/tcp open      https

[result] 3 open, 3 filtered (3m 44.3s) -> #NFID
```

Metadata belongs in:

```bash
show #NFID
```

## `show #JOB` Output

```bash
bl[#NFID] ❯ show #NFID

[job]

id          : #NFID
module      : recon
target      : 10.0.0.1
type        : ip
strategy    : balanced
speed       : normal
probe       : surface
created     : 2026-04-25 00:33
status      : completed
reverse_dns : none

steps       : 5
results     : 1
```

If reverse DNS exists:

```bash
reverse_dns : router.local
```

If none:

```bash
reverse_dns : none
```

## Job Data Model

Store structured data, not just stdout.

```json
{
  "id": "NFID",
  "module": "recon",
  "target": "10.0.0.1",
  "target_type": "ip",
  "params": {
    "strategy": "balanced",
    "speed": "normal",
    "probe": "surface"
  },
  "created": "2026-04-25T00:33:00-04:00",
  "status": "completed",
  "steps": [
    {
      "name": "reverse_dns",
      "status": "completed",
      "results": []
    },
    {
      "name": "ipintel",
      "status": "completed",
      "results": [
        {
          "asn": "AS15169",
          "org": "Google LLC",
          "location": "US / CA / Mountain View",
          "latency": 19.8,
          "vpn_likely": true,
          "confidence": "high"
        }
      ]
    },
    {
      "name": "http_ip_probe",
      "status": "completed",
      "results": [
        {
          "url": "http://10.0.0.1",
          "status_code": 200,
          "title": null
        }
      ]
    },
    {
      "name": "port_scan",
      "tool": "nmap",
      "status": "completed",
      "command": "nmap -Pn -T3 -p 1-1024 10.0.0.1",
      "results": [
        {
          "port": 53,
          "protocol": "tcp",
          "state": "open",
          "service": "domain"
        },
        {
          "port": 80,
          "protocol": "tcp",
          "state": "open",
          "service": "http"
        },
        {
          "port": 443,
          "protocol": "tcp",
          "state": "open",
          "service": "https"
        }
      ]
    }
  ],
  "ipintel": {
    "asn": "AS15169",
    "org": "Google LLC",
    "location": "US / CA / Mountain View",
    "latency": 19.8,
    "vpn_likely": true,
    "confidence": "high",
    "jitter": 5.9,
    "bandwidth": 0.64,
    "trace": []
  },
  "summary": {
    "open_ports": 3,
    "filtered_ports": 3,
    "elapsed": "3m 44.3s"
  }
}
```

## Strategy / Speed / Probe Meaning

Keep these high-level and user-friendly.

### `strategy`

Controls how much recon is performed.

```text
surface    passive registration and ordinary web evidence; no port scan
balanced   default full evidence set
deep       full evidence set with deep network intelligence and aggressive scanning

`fast` remains a compatibility alias for the surface evidence set. `quiet` and
`udp` retain their scan-specific behavior while using the balanced evidence set.
```

### `speed`

Controls scan aggressiveness and timeouts.

```text
slow
normal
fast
```

For nmap mapping:

```text
slow    -> -T2
normal  -> -T3
fast    -> -T4
```

### `probe`

Controls how invasive or noisy the probing is.

```text
surface   light checks only
standard  normal checks
deep      heavier enumeration
```

For now, keep default:

```text
strategy=balanced
speed=normal
probe=surface
```

## Pipeline Selection

### IP target

```text
reverse_dns
ipintel
http_ip_probe
http_vhost_probe if PTR exists
port_scan
```

### Domain target

```text
dns
resolve IP
ipintel
http_probe
port_scan
subdomain later
```

### URL target

```text
http_probe
dns on hostname
ipintel
optional port_scan on hostname
```

## Step Isolation Rule

Each recon step must:

- not depend on side effects from other steps
- only consume defined inputs such as target or resolved IP
- produce structured output independently

This ensures steps remain replaceable and testable.

## Execution Map

Principle:

```text
each recon step = one responsibility = one primary tool (or fallback)
```

### `reverse_dns`

Purpose:

```text
resolve IP -> domain hint
```

Primary tools:

```text
dig -x <ip>
socket.gethostbyaddr()
```

Output:

```text
PTR records
```

### `dns`

Purpose:

```text
resolve domain -> records
```

Primary tool:

```text
dnspython
```

Fallback:

```text
dig
```

Records collected:

```text
A
AAAA
MX
NS
TXT (optional)
```

### `ipintel`

Purpose:

```text
enrich IP with intelligence
```

Primary tool:

```text
yougotmapped
```

Mapping:

```text
geo/asn    -> default
latency    -> -p
jitter     -> -j
bandwidth  -> -b
trace      -> -t
anonymity  -> -c
full       -> -a
```

Blackline behavior:

```text
default -> partial
deep    -> -a
```

### `http_probe`

Purpose:

```text
check web service
```

Primary tool:

```text
requests
```

Fallback:

```text
curl
```

Extract:

```text
status code
headers
title
redirects
```

### `http_ip_probe`

Purpose:

```text
test IP directly
```

Tool:

```text
same as http_probe
```

Targets:

```text
http://<ip>
https://<ip>
```

### `http_vhost_probe`

Purpose:

```text
test domains from reverse DNS or DNS resolution
```

Tool:

```text
requests + Host header
```

Example:

```text
headers = {"Host": "example.com"}
```

### `port_scan`

Purpose:

```text
discover open services
```

Tool:

```text
nmap
```

Base command:

```text
nmap -Pn -T3 -p 1-1024 <target>
```

Future upgrades:

```text
-sV   service detection
-sC   default scripts
```

### Future steps

```text
subdomain -> subfinder / assetfinder / amass later
whois     -> whois
```

## Tool Abstraction Layer

Do not do this:

```text
[info] running dig...
[info] running curl...
```

That leaks the backend.

Do this:

```text
[dns]
[ipintel]
[http]
```

Exception:

```text
nmap -Pn -T3 -p 1-1024 10.0.0.1
```

The raw nmap command is allowed because users recognize it.

## Fallback Strategy

Each step should support fallback:

```text
DNS         -> dnspython -> dig
HTTP        -> requests -> curl
reverse_dns -> socket -> dig -x
ipintel     -> yougotmapped -> API fallback later
```

## Signal vs Noise Principle

Core principle:

```text
recon output shows signals, not raw data
```

Show by default:

```text
ports
HTTP status
DNS records
ASN / org
basic latency
```

Hide by default:

```text
traceroute
jitter
MSS / MTU
bandwidth math
```

Reveal only in:

```text
strategy=deep
```

Default recon shows:

- actionable signals
- key findings

Deep recon reveals:

- diagnostic data
- network characteristics
- extended analysis

The default experience must remain readable in under 5 seconds.

## Error Handling

Each step can fail independently.

Do not fail the whole recon unless the target is invalid or every critical step
fails.

Example:

```bash
[reverse_dns]
none

[http]
http://10.0.0.1       failed
https://10.0.0.1      failed

nmap -Pn -T3 -p 1-1024 10.0.0.1
...

[result] recon complete with warnings (3m 44.3s) -> #NFID
```

Store per-step statuses:

```json
{
  "name": "http_ip_probe",
  "status": "failed",
  "error": "connection timed out"
}
```

## Execution Control

Each step should support:

- timeout limits
- graceful cancellation
- partial result return

Example:

```text
if port_scan times out:
    still return dns + http + ipintel results
```

## Data Provenance

Each result should internally track:

- source tool such as nmap or yougotmapped
- timestamp
- confidence if applicable

This is not displayed by default but is stored for reports.

## Result Summary Rules

Be accurate. Do not call filtered ports open.

Bad:

```bash
[result] 6 open ports
```

Good:

```bash
[result] 3 open, 3 filtered (3m 44.3s) -> #NFID
```

Or:

```bash
[result] 3 open ports (3m 44.3s) -> #NFID
```

If including all interesting ports:

```bash
[result] 3 open, 6 interesting (3m 44.3s) -> #NFID
```

Every recon run must end with:

```text
[result] ...
```

The summary must include:

```text
key findings
elapsed time if meaningful
job ID
```

## Completion States

A recon job can end in:

- completed
- completed_with_warnings
- partial
- failed

The summary line should reflect this state.

## Output Stability Contract

Output format must remain stable across versions unless:

- explicitly versioned
- documented in the changelog

This ensures scripts and workflows relying on Blackline do not break.

## Prompt Behavior

Root:

```bash
blackline ❯
```

Inside job:

```bash
bl[#NFID] ❯
```

For inline recon, the current direction is to auto-enter the created job after
run:

```bash
[info] entered job #NFID
...
bl[#NFID] ❯
```

Keep this consistent.

## Performance Notes

```text
DNS + HTTP -> fast
ipintel    -> medium
nmap       -> slowest
```

Future optimization direction:

```text
parallel: dns + ipintel + http
then:     port_scan
```

## Future Extensions

Later, recon can support:

```bash
recon[target=example.com, modules=dns,http]
recon[target=example.com, exclude=subdomain]
recon[target=example.com, strategy=deep]
```

Future modules:

```text
subdomain
whois
tls
headers
tech_detect
banner_grab
dir_enum
```

Do not add all of these at once. Build the core pipeline first.

## Final Principle

```text
recon is the user-facing workflow.
tools are internal atomic steps.
jobs are the memory.
reports are the final product.
```

Each step must remain:

```text
independent
replaceable
structured
```
