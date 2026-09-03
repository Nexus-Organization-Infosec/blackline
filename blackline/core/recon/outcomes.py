"""Canonical result taxonomy shared by execution, UI, and job storage."""

from __future__ import annotations

DONE = "done"
NEGATIVE = "negative"
SKIPPED = "skipped"
WARNING = "warning"
FAILED = "failed"
RESULT_OUTCOMES = frozenset({DONE, NEGATIVE, SKIPPED, WARNING, FAILED})


def classify_result(*, tool: str, ok: bool, payload: dict[str, object], error: str = "") -> str:
    """Classify execution semantics, not merely whether a command returned zero."""
    explicit = str(payload.get("result_outcome", "")).strip().lower()
    if explicit in RESULT_OUTCOMES:
        return explicit
    if payload.get("skipped"):
        return SKIPPED
    if payload.get("negative_observation"):
        return NEGATIVE
    if tool == "http" and _all_http_findings_closed(payload):
        return NEGATIVE
    if not ok:
        return FAILED
    warnings = payload.get("warnings", [])
    if isinstance(warnings, list) and warnings:
        return WARNING
    findings = payload.get("findings", [])
    if tool == "http" and isinstance(findings, list) and any(
        isinstance(finding, dict) and not finding.get("ok", False) for finding in findings
    ):
        return WARNING
    return DONE


def outcome_is_success(outcome: str) -> bool:
    """Return whether an outcome means Blackline completed the observation."""
    return outcome in {DONE, NEGATIVE, SKIPPED, WARNING}


def completion_state_for(outcome: str) -> str:
    """Map granular outcomes into the legacy aggregate job status vocabulary."""
    if outcome == FAILED:
        return "failed"
    if outcome == WARNING:
        return "completed_with_warnings"
    return "completed"


def _all_http_findings_closed(payload: dict[str, object]) -> bool:
    findings = payload.get("findings", [])
    return isinstance(findings, list) and bool(findings) and all(
        isinstance(finding, dict)
        and finding.get("status_code") is None
        and "connection refused" in str(finding.get("error", "")).lower()
        for finding in findings
    )
