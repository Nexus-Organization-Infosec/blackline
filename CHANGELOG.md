# Changelog

All notable changes to Blackline are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- GitHub Actions CI for supported Python versions.
- Community, contribution, and security project files.
- Versioned planning contracts for step identities, capabilities, dependencies,
  retries, artifacts, events, and deterministic serialization.
- A validated capability/provider registry with handler, timeout, dependency,
  priority, input, output, and strategy metadata.
- Registered execution-handler families for discovery, web, TLS, and network
  capabilities.
- Canonical, provenance-aware artifacts and a deterministic per-run artifact
  store for cross-step evidence exchange.
- Validated execution-plan dependency graphs with stable topological waves,
  cycle detection, and required-artifact skip behavior.
- A bounded generic scheduler with deterministic result ordering, per-step
  retries, cooperative cancellation, and dependency-failure propagation.
- A unified, versioned execution-event stream covering plans, steps, retries,
  artifacts, cancellation, and subprocess diagnostics.
- A versioned job domain model and swappable repository contract with atomic,
  backward-compatible JSON persistence.
- Optional JSONL execution-event journaling and failure-isolated event fan-out.

### Changed

- Consolidated duplicate planner branches and removed the unused legacy
  engine-pipeline wrapper.
- Replaced the central tool-specific executor branch chain with generic
  provider-to-handler dispatch.
- Replaced implicit runtime-state keys with typed artifacts while preserving
  existing result payloads and saved-job compatibility.
- Routed verbose recon diagnostics through structured execution events while
  retaining the existing progress and command callbacks as compatibility APIs.
- Moved job normalization and aggregation out of the CLI and file operations
  behind the storage boundary; a database remains unnecessary for current use.

## [0.1.0] - 2026-08-30

### Added

- Initial development release with the `recon` workflow.
