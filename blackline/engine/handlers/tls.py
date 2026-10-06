"""TLS certificate and configuration execution handlers."""

from __future__ import annotations

from blackline.engine.handlers.base import HandlerContext, artifact, to_port
from blackline.engine.models import PlanStep, StepResult
from blackline.tools.tls.inspector import inspect_tls
from blackline.tools.tls.sslyze import inspect_tls_configuration


def execute_tls(step: PlanStep, context: HandlerContext) -> StepResult:
    result = inspect_tls(
        str(step.params.get("host", "")),
        port=to_port(step.params.get("port", "443")),
        server_name=str(step.params.get("server_name", "")),
        timeout_seconds=step.timeout_seconds if step.timeout_seconds is not None else 10.0,
    )
    payload = {
        "target": step.params.get("target", ""),
        "host": result.host,
        "port": result.port,
        "subject": result.subject,
        "issuer": result.issuer,
        "sans": list(result.sans),
        "not_before": result.not_before,
        "not_after": result.not_after,
        "days_until_expiry": result.days_until_expiry,
        "protocol": result.protocol,
        "cipher": result.cipher,
        "certificate_sha256": result.certificate_sha256,
        "provider": result.provider,
        "certificate_parser": result.certificate_parser,
        "warnings": list(result.warnings),
        "raw_output": result.raw_output,
        "negative_observation": "connection refused" in result.error.lower(),
        "elapsed_seconds": result.elapsed_seconds,
    }
    artifacts = ()
    if result.ok:
        artifacts = (
            artifact(
                step,
                "tls.certificate",
                f"{result.host}:{result.port}",
                {
                    "subject": result.subject,
                    "issuer": result.issuer,
                    "sans": list(result.sans),
                    "not_before": result.not_before,
                    "not_after": result.not_after,
                    "sha256": result.certificate_sha256,
                    "protocol": result.protocol,
                    "cipher": result.cipher,
                },
                provider=result.provider,
                confidence=1.0,
            ),
        )
    return StepResult(step.tool, step.action, result.ok, payload, result.error, artifacts=artifacts)


def execute_sslyze(step: PlanStep, context: HandlerContext) -> StepResult:
    result = inspect_tls_configuration(
        str(step.params.get("host", "")),
        port=to_port(step.params.get("port") or "443"),
        timeout_seconds=step.timeout_seconds or 45.0,
        executor=context.command_executor,
    )
    payload = {
        "host": result.host,
        "port": result.port,
        "provider": "sslyze",
        "scans": [
            {
                "host": scan.host,
                "port": scan.port,
                "protocols": list(scan.protocols),
                "ciphers": list(scan.ciphers),
                "findings": list(scan.findings),
            }
            for scan in result.scans
        ],
        "skipped": result.skipped,
        "negative_observation": result.negative_observation,
        "raw_output": result.raw_output,
        "elapsed_seconds": result.elapsed_seconds,
    }
    artifacts = tuple(
        artifact(
            step,
            "tls.configuration",
            f"{scan.host}:{scan.port}",
            {"protocols": list(scan.protocols), "ciphers": list(scan.ciphers), "findings": list(scan.findings)},
            provider="sslyze",
            confidence=1.0,
        )
        for scan in result.scans
    )
    return StepResult(step.tool, step.action, result.ok, payload, result.error, artifacts=artifacts)


HANDLERS = (
    ("tls", execute_tls),
    ("sslyze", execute_sslyze),
)
