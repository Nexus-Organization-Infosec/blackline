# Extending Blackline

New capabilities should fit the existing contracts instead of adding branches
to the executor or file operations to the CLI.

## Capability Path

An extension has four parts:

1. Define its capability, inputs, outputs, timeout, and strategy metadata.
2. Implement a handler that accepts `PlanStep` and `HandlerContext` and returns
   `StepResult` with canonical artifacts.
3. Register the handler by provider name in a `HandlerRegistry`.
4. Execute through `ExecutionRuntime` with the desired scheduler and observers.

The handler owns provider-specific translation. The scheduler only sees steps,
dependencies, retry policy, results, and artifacts.

```python
registry = HandlerRegistry()
registry.register("example", collect_example)

runtime = ExecutionRuntime(
    handler_registry=registry,
    scheduler_options=SchedulerOptions(max_concurrency=4),
    event_callback=journal.append,
)

results = runtime.execute(plan)
```

No change to `executor.py` or `scheduler.py` is needed for another provider.
Built-in providers should also be added to `config/recon_tools.json` so normal
planning can select them by capability.

## Result and Artifact Rules

- Return one `StepResult` for every final step outcome.
- Use canonical outcomes: `done`, `negative`, `warning`, `skipped`, or `failed`.
- Put cross-step facts in `Artifact`; payloads remain available for reports.
- Declare produced and consumed artifact kinds in provider metadata.
- Add explicit dependencies only when a step cannot run without upstream work.
- Configure retries narrowly by canonical outcome and keep them bounded.

`StepResult.to_dict()` provides the stable persistence representation for a
generic integration. Feature-specific presentation may add a curated summary.

## Observability and Persistence

Execution emits versioned events independently of verbose rendering. Use
`fanout_event_callbacks` when UI, JSONL journaling, or telemetry all need the
same stream. Consumer failures are isolated from execution.

Jobs use the `JobRepository` contract. JSON is the default adapter; SQLite can
be introduced later without changing plans, handlers, scheduling, or rendering.
See [Storage Decision](storage-decision.md) for the migration threshold.

## Compatibility Rules

- Add fields with defaults and keep serialized schemas versioned.
- Keep result ordering deterministic.
- Read legacy saved jobs even after the write format expands.
- Preserve public imports during migrations.
- Add an end-to-end extension test before introducing a new integration seam.
