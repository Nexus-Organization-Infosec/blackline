# CLT v0

CLT is Blackline's small, deterministic workflow and capability language. It describes intent and control flow; it is not a general-purpose programming language and it never evaluates Python or shell syntax.

```text
target = 127.0.0.1

recon[target, strategy=deep]
    -> analyze

    if port 22 open
        -> inspect ssh
```

The supported v0 constructs are assignments, operations, `->` flows, `if`/`else` blocks, four-space indentation, and `#` comments. Operation inputs and named options use square brackets, for example `recon[target, strategy=deep]`.

## Deterministic phrases

Conditions permit limited word-order flexibility where semantic roles are unique. These normalize identically:

```text
if port 22 open
if open port 22
if port open 22
```

They all compile to the canonical condition `port / 22 / open`. Ambiguous or incomplete phrases fail with a source-oriented diagnostic rather than being guessed.

Actions also accept the unambiguous equivalent forms `inspect ssh` and `ssh inspect`.

## Python API

```python
from blackline.clt import CLTRuntime, CapabilityRegistry, compile_source

workflow = compile_source('''
target = 127.0.0.1
recon[target]
    if port 22 open
        -> inspect ssh
''')

registry = CapabilityRegistry()
registry.register("recon", handler=lambda call: {"target": call.inputs[0]})
registry.register("inspect", "ssh", handler=lambda call: {"service": "ssh"})

result = CLTRuntime(registry).run(workflow, facts={("port", "22"): "open"})
```

Plugins can extend the domain vocabulary and provide action handlers:

```python
from blackline.clt import WordClass, default_vocabulary

vocabulary = default_vocabulary()
vocabulary.register("redis", WordClass.DOMAIN)
registry.register("inspect", "redis", handler=inspect_redis)
```

Compilation and runtime resolution are intentionally separate. A workflow can compile against registered vocabulary before its capabilities are installed; execution then gives a clear `capability unavailable` error if no handler is registered.
