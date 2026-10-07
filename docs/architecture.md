# Architecture

## Boundary Rule

Blackline should follow this layering:

```text
CLI = what the user sees
core = what the system thinks
tools = how the system executes
storage = what the system remembers
```

Current high-level flow:

```text
cli -> engine -> core -> tools -> storage
```

## Top-Level Structure

```text
blackline/
├── cli/
├── engine/
├── core/
├── tools/
├── storage/
├── config/
├── operators/
├── utils/
```

## Responsibilities

### `cli/`

User interface only.

- prompt
- command parsing
- user-facing output
- shell interaction

CLI folders should reflect user concepts, not backend implementation details.

Preferred direction:

```text
cli/commands/system/
cli/commands/recon/
cli/commands/network/
cli/commands/utils/
```

### `engine/`

Execution brain.

- runner orchestrates one execution
- runtime composes handlers, scheduler policy, command execution, and observers
- planner builds the pipeline
- executor exposes the public execution API and dispatches registered handlers
- scheduler owns bounded concurrency, retries, dependency outcomes, and cancellation
- events provide one versioned stream for plan, step, artifact, and command activity
- handlers translate plan steps into tool-adapter calls
- graph validates dependencies and creates deterministic execution waves
- models define stable planning and execution contracts

Preferred direction:

```text
engine/context.py
engine/session.py
engine/runner.py
engine/runtime.py
engine/planner.py
engine/executor.py
engine/scheduler.py
engine/events.py
engine/handlers/
engine/graph.py
engine/models.py
```

### `core/`

Domain logic layer.

This is the missing separation that keeps feature logic out of raw tool
wrappers.

Example direction:

```text
core/recon/
  steps/
    dns.py
    ipintel.py
    http.py
    port_scan.py
  pipeline.py
  models.py
```

`core/` should decide:

- which recon steps exist
- what order they run in
- what data each step consumes
- what structured outputs each step produces

Canonical artifacts in `core/artifacts.py` are the cross-step data contract.
Tool-specific payloads remain available for reports and compatibility, but
handlers communicate DNS addresses, ports, services, web endpoints, TLS data,
and other facts through the artifact store.

### `tools/`

External execution adapters and wrappers.

Tools should be grouped by capability, not by product feature.

Preferred direction:

```text
tools/network/
  nmap.py
  traceroute.py
tools/dns/
  resolver.py
tools/http/
  client.py
  curl_probe.py
tools/intel/
  yougotmapped.py
tools/parsers/
  nmap.py
  curl.py
```

### `storage/`

Persistence only.

```text
storage/job_store.py
storage/event_journal.py
storage/jobs/
storage/history/
storage/cache/
```

`cache/` is reserved for repeatable lookups such as DNS and IP intelligence.
The canonical `Job` model and aggregation rules live in `core/jobs.py`; the
storage layer implements repositories for those models. JSON is the current
adapter, not an engine or CLI contract. See [Storage Decision](storage-decision.md).

### `config/`

Configuration and schema definitions.

Current files are good:

```text
config/commands.json
config/tools.json
config/operators.json
```

Longer term, these may evolve into a more explicit schema grouping, but no
rewrite is required now.

Planner decides what.
Tools decide how.

The provider registry is the authoritative bridge between those layers. It
defines each provider's canonical capability, handler, supported strategies,
timeout, dependencies, consumed artifacts, and produced artifacts. The generic
executor must not branch on provider names; provider-specific payload shaping
belongs in `engine/handlers/`.

Plans form a directed acyclic graph. Dependencies determine execution order;
the scheduler retains execution-group inference only for legacy plans created
outside the planner.

The scheduler executes graph waves with a fixed concurrency ceiling and keeps
results in plan order. Retry policy belongs to each step, required dependency
failures become explicit skipped results, and cancellation stops new work while
allowing already-running handlers to finish cooperatively.

Every run emits the same versioned `ExecutionEvent` contract. CLI verbosity,
future persistence, telemetry, and machine-readable output can consume plan,
step, retry, artifact, cancellation, and subprocess events without coupling to
handler implementations. Legacy progress and command callbacks remain adapters
during migration.

Event consumers can be fanned out independently. The optional JSONL journal
provides replayable execution history without making persistence mandatory or
coupling the scheduler to a database.

`ExecutionRuntime` is the public composition root for embedded use and future
applications. It centralizes replaceable services without turning them into
global state. See [Extending Blackline](extending.md) for the supported provider
and integration path.

`tool_loader` should remain a configuration accessor, not a second planner.

## Why This Matters

This split improves:

- separation of concerns
- future extensibility
- testability
- readability

It also makes the recon stack cleaner:

```text
recon_cmd -> engine -> core.recon -> tools -> result
```

instead of mixing feature logic directly into tool wrappers.

## Migration Approach

This is an evolution, not a rewrite.

- keep current paths working
- add clearer layers beside them
- move logic gradually
- remove compatibility paths only after tests and behavior are stable

The current tree already removed the duplicate CLI command layer, the old
`engine/state` package, the old `tools/recon` package, and the temporary
`tools/probes` package. The remaining migration work is to move more real recon
logic into `core/recon/` and reduce the amount of feature behavior living in
CLI adapters.
