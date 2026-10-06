# Storage Decision

Blackline does not need a database yet. Jobs are small, locally owned records,
the CLI reads them by identifier or lists all of them, and current execution
does not require relational queries or concurrent writers.

The architecture now separates those facts from the storage technology:

```text
core/jobs.py                job model, migration, aggregation
storage/job_store.py        repository contract and JSON adapter
storage/event_journal.py    optional append-only execution events
cli/                        presentation and user interaction only
```

JSON remains the default because it is inspectable, portable, and sufficient
for the current access pattern. Writes use a temporary file and atomic replace,
legacy records are upgraded in memory, corrupt records are isolated during
listing, and every saved job carries a schema version.

A database adapter becomes worthwhile when at least one of these is real:

- multiple processes must update the same job;
- operators need indexed searches across many jobs or artifacts;
- event volume makes replaying JSONL noticeably slow;
- relationships between targets, observations, and runs need cross-job queries;
- retention, transactions, or migrations need stronger guarantees.

At that point, implement the existing `JobRepository` contract with SQLite and
change repository selection. The core job model, engine, scheduler, handlers,
CLI renderers, and saved-result semantics do not need to change.

Execution-event journaling is optional. A caller can pass
`JsonlEventJournal.append` as the engine event callback, or combine it with UI
and telemetry consumers through `fanout_event_callbacks`. Command output is
therefore persisted only when an operator or integration explicitly enables it.
