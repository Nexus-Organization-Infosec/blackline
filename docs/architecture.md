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
- planner builds the pipeline
- executor runs planned steps
- pipeline defines execution-level step structures

Preferred direction:

```text
engine/context.py
engine/session.py
engine/runner.py
engine/planner.py
engine/executor.py
engine/pipeline.py
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
storage/jobs/
storage/history/
storage/cache/
```

`cache/` is reserved for repeatable lookups such as DNS and IP intelligence.

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
