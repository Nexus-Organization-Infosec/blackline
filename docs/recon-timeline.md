# Recon Timeline

This timeline turns [recon-design.md](https://github.com/Nexus-Organization-Infosec/blackline/blob/dev/v0.1.0/docs/recon-design.md)
into an implementation sequence we can execute step by step.

## Execution Board

This is the working order we should follow from the current repo state.

| Phase | Focus | Status | Why It Comes Now |
| --- | --- | --- | --- |
| 0 | Baseline stabilization | Complete | We needed a stable shell and recon base before expanding behavior. |
| 1 | Target normalization | Complete | Everything else depends on correct `ip` / `domain` / `url` typing. |
| 2 | Job model upgrade | Complete | We needed report-ready storage before adding richer recon data. |
| 3 | Core recon pipeline | Complete | This moved workflow ownership out of the CLI and into `core/recon`. |
| 4 | DNS step | Complete | Domain recon needed a real first-class resolver step. |
| 5 | IP intelligence | Complete | `ipintel` is core context for both IP and domain flows. |
| 6 | HTTP probing | Complete | HTTP is now a real step instead of an incidental add-on. |
| 7 | Port scan step | Complete | `nmap` is now a structured recon step rather than the identity of recon. |
| 8 | Completion states | Complete | Multi-step recon needed honest summary and job status handling. |
| 9 | Execution control | Complete | We needed timeouts, cancellation, and partial results before scale-up. |
| 10 | Parallel fast steps | Complete | Good optimization, but only after deterministic step behavior was solid. |
| 11 | Report surface | Next | Reporting becomes much easier once structured storage is stable. |
| 12 | Future modules | Later | Expansion should happen only after the core pipeline is trustworthy. |

## Current Working Slice

If we want the highest leverage with the least churn, this is the immediate
implementation lane:

1. Phase 1 — Target normalization
2. Phase 2 — Job model upgrade
3. Phase 3 — Core recon pipeline

These three phases form the foundation for everything else in the design note.
If we skip them and jump straight into more tools, we will keep paying for fuzzy
boundaries.

## Immediate Action List

This is the concrete step list we can execute next:

1. Enrich `show #JOB` with fuller per-step metadata and provenance.
2. Prepare a stable report-oriented shape without bloating normal shell output.
3. Keep `show #JOB` readable while exposing stored step history more clearly.
4. Add tests around report-ready data presence and output stability.
5. Preserve backward compatibility for older job JSON while expanding the report surface.

## Definition Of Ready

Before we start a phase, we should know:

- which file owns the behavior
- which test file proves it
- what user-visible output changes
- what structured job data must be stored

## Definition Of Done

A phase is only done when:

- tests for the affected layer pass
- docs reflect the final behavior
- output stays stable for existing flows
- job data remains backward-safe and does not corrupt existing records

## Principles

Every phase should preserve:

- deterministic pipeline behavior
- idempotent job creation
- native-feeling output
- structured result storage
- stable output contracts

Each phase should end with:

- passing tests for the affected layer
- updated docs if behavior changes
- no regression in existing `recon[...]` flows

## Phase 0 — Baseline Stabilization

Goal:

```text
make current recon stable enough to extend
```

Deliverables:

- keep `recon[...]` job auto-creation consistent
- keep result summaries accurate
- keep config and prompt failures soft instead of crashing
- keep the new package boundaries green

Done means:

- `recon[...]` runs without duplicate summaries
- missing config does not crash the shell
- structure and architecture tests pass

Status:

```text
complete
```

Completed baseline checks:

- `recon[...]` auto-job entry stays consistent even if help config is unavailable
- recon summary output stays single-pass and counts only open ports accurately
- missing config and completion failures degrade into soft errors instead of shell crashes
- the full test suite passes against the current package boundaries

## Phase 1 — Target Normalization

Goal:

```text
detect target type and normalize input before planning steps
```

Build:

- `core/recon/models.py`
  - add normalized target model for `ip`, `domain`, `url`
- `core/recon/pipeline.py`
  - add target-type aware pipeline container
- URL normalization:
  - scheme
  - host
  - port
  - path

Tests:

- `test_pipeline.py`
  - ip detection
  - domain detection
  - url detection
  - malformed target rejection

Done means:

- same input always yields same target type
- planner receives normalized target context

Status:

```text
complete
```

Completed target-normalization checks:

- `ip`, `domain`, and `url` targets normalize into a deterministic `ReconTarget`
- malformed targets are rejected before recon execution
- `ExecutionContext` now carries normalized target data for recon runs
- planner uses normalized host data so URL targets plan against the host, not the full URL

## Phase 2 — Job Model Upgrade

Goal:

```text
make jobs report-ready before adding more recon steps
```

Build:

- expand job storage to include:
  - `target`
  - `target_type`
  - `params`
  - `status`
  - `steps`
  - `summary`
  - `ipintel`
- add completion states:
  - `completed`
  - `completed_with_warnings`
  - `partial`
  - `failed`
- add provenance fields:
  - tool
  - timestamp
  - confidence

CLI updates:

- `show #JOB` reads upgraded fields
- root output still stays minimal

Tests:

- `test_jobs_command.py`
  - show upgraded metadata
  - preserve old jobs without corruption

Done means:

- jobs hold structured data, not just loosely appended payloads
- `show #JOB` becomes the metadata home

Status:

```text
complete
```

Completed job-model checks:

- persisted jobs now carry `target`, `target_type`, `steps`, `summary`, and `ipintel`
- `show #JOB` renders upgraded metadata instead of only raw params
- older job JSON still loads safely and is upgraded on read without corruption
- recon step persistence now updates job status and summary instead of only appending loose result blobs

## Phase 3 — Core Recon Pipeline

Goal:

```text
move recon decision-making into core/recon
```

Build:

- `core/recon/steps/dns.py`
- `core/recon/steps/ipintel.py`
- `core/recon/steps/http.py`
- `core/recon/steps/port_scan.py`
- `core/recon/pipeline.py`
  - define ordered steps by target type

Pipeline rules:

- IP:
  - `reverse_dns`
  - `ipintel`
  - `http_ip_probe`
  - `http_vhost_probe` if PTR exists
  - `port_scan`
- Domain:
  - `dns`
  - resolve IP
  - `ipintel`
  - `http_probe`
  - `port_scan`
- URL:
  - `http_probe`
  - `dns`
  - `ipintel`
  - optional `port_scan`

Tests:

- `test_pipeline.py`
  - ip pipeline order
  - domain pipeline order
  - url pipeline order
  - determinism

Done means:

- CLI no longer decides recon workflow shape
- engine asks `core.recon` what steps should exist

Status:

```text
complete
```

Completed pipeline checks:

- target-type workflow order now lives in `blackline/core/recon/pipeline.py`
- ordered recon steps are defined in `blackline/core/recon/steps/`
- engine planning now consumes the core recon pipeline instead of hardcoding recon shape directly
- current execution behavior stays stable while the architecture boundary moves into `core/recon`

## Phase 4 — DNS Step

Goal:

```text
implement real domain dns records with structured storage
```

Build:

- `tools/dns/resolver.py`
  - primary: `dnspython`
  - fallback: `dig`
- `core/recon/steps/dns.py`
  - collect `A`, `AAAA`, `MX`, `NS`
  - optional `TXT`

Output:

```text
[dns]
A
AAAA
MX
```

Storage:

- full raw result
- summarized display rows

Tests:

- `test_dns_step.py`
- pipeline integration coverage

Done means:

- domain targets show real DNS sections
- resolved IPs are available to downstream steps

Status:

```text
complete
```

Completed DNS checks:

- domain and URL recon now execute a structured DNS step before port scanning
- DNS resolution returns structured `A`, `AAAA`, `MX`, and `NS` records with clean fallback behavior
- recon output can render a native `[dns]` section without breaking existing nmap flow
- resolved IPs are stored in the DNS payload for downstream recon work

## Phase 5 — IP Intelligence Step

Goal:

```text
add ipintel as context enrichment, not exposure detection
```

Build:

- `tools/intel/yougotmapped.py`
- `core/recon/steps/ipintel.py`

Default mode:

- ASN
- org
- location
- latency
- anonymity signal

Deep mode:

- jitter
- bandwidth estimate
- trace
- MSS / MTU later

Storage:

- raw tool result
- normalized `ipintel` block on job
- provenance and confidence

Tests:

- `test_ipintel.py`
  - default output
  - deep output
  - failure fallback
  - no false ownership claims

Done means:

- IP and resolved domain targets can be enriched consistently
- `show #JOB` can display summarized `ipintel`

Status:

```text
complete
```

Completed IP-intelligence checks:

- recon now executes a structured `ipintel` step for IP and DNS-resolved domain flows
- resolved domain targets hand off their first resolved IP into `ipintel`
- recon output can render concise `[ipintel]` and `[anonymity]` sections
- jobs now store a normalized `ipintel` block for `show #JOB`

## Phase 6 — HTTP Probing

Goal:

```text
support http_probe, http_ip_probe, and http_vhost_probe
```

Build:

- `tools/http/client.py`
  - primary: `requests`
  - fallback: `curl`
- `tools/http/curl_probe.py`
- `tools/parsers/curl.py`
- `core/recon/steps/http.py`

Collect:

- status code
- redirects
- headers
- title

Modes:

- `http_probe`
- `http_ip_probe`
- `http_vhost_probe`

Tests:

- `test_http_probe.py`
  - direct IP probing
  - domain probing
  - host-header probing
  - timeout/failure behavior

Done means:

- recon can produce meaningful web-service output before port scan finishes

Status:

```text
complete
```

Completed HTTP checks:

- recon now executes real `http_probe` and `http_ip_probe` steps
- domain, URL, and direct-IP HTTP probing produce structured findings with status, title, and redirect data
- recon output can render a concise `[http]` section without bloating the shell
- HTTP findings are stored as structured job-step data for later reporting

## Phase 7 — Port Scan Step

Goal:

```text
finish the port_scan step as a structured module inside the recon pipeline
```

Build:

- keep `tools/network/nmap.py` as the single execution source
- `tools/parsers/nmap.py` remains the parser source
- `core/recon/steps/port_scan.py`
  - map `strategy`, `speed`, `probe` into scan behavior

Output:

- raw nmap command allowed
- native `PORT / STATE / SERVICE` display
- correct summary counts:
  - open
  - filtered
  - optional interesting

Tests:

- `test_nmap_tool.py`
- `test_port_scan_step.py`

Done means:

- port scanning is just one step in recon, not the whole recon identity

Status:

```text
complete
```

Completed port-scan checks:

- the port-scan payload now carries explicit `open`, `filtered`, and `interesting` counts
- recon summaries can report mixed-state results honestly, such as `3 open, 3 filtered`
- fallback table rendering now shows filtered ports instead of hiding them when raw nmap output is absent
- port-scan logic is tested directly in `tests/test_port_scan_step.py`

## Phase 8 — Completion State Aggregation

Goal:

```text
make recon summary and job status reflect multi-step reality
```

Build:

- aggregate per-step status into job completion state
- summary line rules:
  - `completed`
  - `completed_with_warnings`
  - `partial`
  - `failed`

Examples:

```text
[result] 3 open, 3 filtered (3m 44.3s) -> #NFID
[result] recon complete with warnings (12.4s) -> #A12F
```

Tests:

- mixed success/failure steps
- partial recon returns usable data

Done means:

- one failing step does not erase successful earlier steps

Status:

```text
complete
```

Completed completion-state checks:

- recon now aggregates per-step outcomes into `completed`, `completed_with_warnings`, `partial`, or `failed`
- mixed-success runs no longer let a successful port scan hide earlier DNS or HTTP failures
- mixed HTTP findings now persist as warnings so stored job status matches user-visible output
- final `[result]` lines reflect both key findings and overall recon state

## Phase 9 — Execution Control

Goal:

```text
support graceful timeout and cancellation across steps
```

Build:

- per-step timeout configuration
- graceful cancellation hooks
- partial result return on timeout

Rules:

- `port_scan` timeout must still return DNS, HTTP, and `ipintel`
- cancellation must not corrupt jobs

Tests:

- timeout on slow step
- cancellation during scan
- partial job persistence

Done means:

- recon behaves like a resilient pipeline instead of a brittle monolith

Status:

```text
complete
```

Completed execution-control checks:

- recon now uses config-backed per-step timeout policy for DNS, `ipintel`, HTTP, and port scan
- cancellation returns already completed step results instead of dropping the whole run
- cancelled runs surface a clear warning and persist partial job state safely
- timeout and cancellation paths are covered at both engine and recon-command layers

## Phase 10 — Parallel Fast Steps

Goal:

```text
improve runtime without breaking determinism
```

Build:

- parallelize:
  - `dns`
  - `ipintel`
  - `http`
- keep:
  - deterministic output order
  - deterministic summary order

Rules:

- execution may be parallel
- presentation order must stay stable

Tests:

- repeated runs preserve output structure
- concurrency does not reorder displayed sections

Done means:

- faster balanced recon
- no randomness in displayed output

Status:

```text
complete
```

Completed parallel-step checks:

- fast recon steps now execute in dependency-safe parallel waves instead of one rigid linear chain
- IP recon can overlap `ipintel` and HTTP immediately, while domain and URL recon parallelize DNS and HTTP before `ipintel`
- result presentation order remains stable even when execution order differs underneath
- concurrency coverage now proves both overlap and deterministic result ordering

## Phase 11 — Report Surface

Goal:

```text
turn stored job data into reporting foundations
```

Build:

- make `show #JOB` richer
- prepare `report #JOB` format
- ensure provenance is available for reporting

Tests:

- `show #JOB` output stability
- report-ready data presence

Done means:

- jobs become useful long after the command finishes

## Phase 12 — Future Modules

Goal:

```text
expand recon only after the core pipeline is solid
```

Candidates:

- `subdomain`
- `whois`
- `tls`
- `headers`
- `tech_detect`
- `banner_grab`
- `dir_enum`

Rule:

```text
do not add these before phases 1 through 10 are stable
```

## Recommended Build Order

If we want the most leverage with the least churn, the next sequence should be:

1. Phase 1 — Target Normalization
2. Phase 2 — Job Model Upgrade
3. Phase 3 — Core Recon Pipeline
4. Phase 4 — DNS Step
5. Phase 5 — IP Intelligence Step
6. Phase 6 — HTTP Probing
7. Phase 7 — Port Scan Step
8. Phase 8 — Completion State Aggregation
9. Phase 9 — Execution Control
10. Phase 10 — Parallel Fast Steps

## Immediate Next Tasks

These are the most actionable next tasks from the current repo state:

1. Add normalized target typing to `core/recon/models.py`.
2. Move recon pipeline selection logic into `core/recon/pipeline.py`.
3. Expand job JSON shape to include `target_type`, `steps`, `summary`, and `ipintel`.
4. Add `test_pipeline.py` and `test_ipintel.py`.
5. Implement real `dns` and `ipintel` step adapters before expanding more recon features.

## Suggested Work Sessions

If we want this to feel manageable instead of huge, this is a good cut:

### Session 1

- finish Phase 1
- add `test_pipeline.py`
- prove deterministic target normalization

### Session 2

- finish Phase 2
- upgrade job storage
- upgrade `show #JOB`

### Session 3

- finish Phase 3
- move recon step selection out of the CLI path
- make engine call `core/recon` for workflow shape
