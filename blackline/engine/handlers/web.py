"""HTTP probing, fingerprinting, and crawling execution handlers."""

from __future__ import annotations

from blackline.engine.handlers.base import HandlerContext, artifact
from blackline.engine.models import PlanStep, StepResult
from blackline.tools.http.client import probe_http
from blackline.tools.http.fingerprint import fingerprint_http
from blackline.tools.http.httpx import discover_http_services, probe_httpx
from blackline.tools.http.katana import crawl_with_katana
from blackline.tools.http.whatweb import fingerprint_with_whatweb


def execute_http(step: PlanStep, context: HandlerContext) -> StepResult:
    arguments = {
        "mode": step.action,
        "host": str(step.params.get("host", "")),
        "scheme": str(step.params.get("scheme", "")),
        "path": str(step.params.get("path", "")),
        "port": str(step.params.get("port", "")),
        "host_header": str(step.params.get("host_header", "")),
        "command_executor": context.command_executor,
    }
    try:
        result = probe_http(
            str(step.params.get("target", "")),
            timeout=step.timeout_seconds if step.timeout_seconds is not None else 10.0,
            **arguments,
        )
    except TypeError:
        result = probe_http(str(step.params.get("target", "")), **arguments)
    payload = {
        "target": step.params.get("target", ""),
        "mode": step.action,
        "provider": result.provider,
        "findings": [
            {
                "url": finding.url,
                "status_code": finding.status_code,
                "title": finding.title,
                "redirect_to": finding.redirect_to,
                "headers": dict(finding.headers),
                "ok": finding.ok,
                "error": finding.error,
            }
            for finding in result.findings
        ],
        "elapsed_seconds": result.elapsed_seconds,
    }
    artifacts = tuple(
        artifact(
            step,
            "web.endpoint",
            finding.url,
            {"status_code": finding.status_code, "reachable": finding.status_code is not None},
            provider=result.provider,
            confidence=1.0,
        )
        for finding in result.findings
    )
    return StepResult(step.tool, step.action, result.ok, payload, result.error, artifacts=artifacts)


def execute_httpx(step: PlanStep, context: HandlerContext) -> StepResult:
    discovered_endpoints = _httpx_discovery_endpoints(context)
    timeout = step.timeout_seconds if step.timeout_seconds is not None else 10.0
    if step.action == "discover_http_services" or discovered_endpoints:
        result = discover_http_services(
            discovered_endpoints or (f"{step.params.get('host', '')}:{step.params.get('port', '')}",),
            timeout_seconds=timeout,
            executor=context.command_executor,
        )
    else:
        result = probe_httpx(
            str(step.params.get("target", "")),
            mode="http_ip_probe" if step.params.get("target_type") == "ip" else "http_probe",
            host=str(step.params.get("host", "")),
            scheme=str(step.params.get("scheme", "")),
            path=str(step.params.get("path", "")),
            port=str(step.params.get("port", "")),
            timeout_seconds=timeout,
            executor=context.command_executor,
        )
    payload = {
        "target": result.target,
        "provider": "httpx",
        "findings": [
            {
                "url": finding.url,
                "status_code": finding.status_code,
                "title": finding.title,
                "redirect_to": finding.redirect_to,
                "technologies": list(finding.technologies),
                "webserver": finding.webserver,
                "tls": dict(finding.tls),
            }
            for finding in result.findings
        ],
        "skipped": result.skipped,
        "negative_observation": result.negative_observation,
        "raw_output": result.raw_output,
        "elapsed_seconds": result.elapsed_seconds,
    }
    artifacts = []
    for finding in result.findings:
        artifacts.append(artifact(step, "web.endpoint", finding.url, {"status_code": finding.status_code, "webserver": finding.webserver, "tls": dict(finding.tls)}, provider="httpx", confidence=1.0))
        artifacts.extend(
            artifact(step, "web.technology", finding.url, {"name": technology}, provider="httpx", confidence=0.8)
            for technology in finding.technologies
        )
    return StepResult(step.tool, step.action, result.ok, payload, result.error, artifacts=tuple(artifacts))


def execute_fingerprint(step: PlanStep, context: HandlerContext) -> StepResult:
    result = fingerprint_http(
        str(step.params.get("target", "")),
        mode="http_ip_probe" if step.params.get("target_type") == "ip" else "http_probe",
        host=str(step.params.get("host", "")),
        scheme=str(step.params.get("scheme", "")),
        path=str(step.params.get("path", "")),
        port=str(step.params.get("port", "")),
        timeout=step.timeout_seconds if step.timeout_seconds is not None else 10.0,
    )
    payload = {
        "target": result.target,
        "server": result.server,
        "framework": result.framework,
        "cms": result.cms,
        "javascript": result.javascript,
        "security_headers": list(result.security_headers),
        "cookies": list(result.cookies),
        "confidence": result.confidence,
        "evidence": list(result.evidence),
        "provider": result.provider,
        "skipped": result.skipped,
        "warnings": list(result.warnings),
        "elapsed_seconds": result.elapsed_seconds,
    }
    artifacts = tuple(
        artifact(step, "web.technology", result.target, {"category": category, "name": value}, provider=result.provider, confidence=0.8)
        for category, value in (
            ("server", result.server),
            ("framework", result.framework),
            ("cms", result.cms),
            ("javascript", result.javascript),
        )
        if value and str(value).lower() != "unknown"
    )
    return StepResult(step.tool, step.action, result.ok, payload, result.error, artifacts=artifacts)


def execute_whatweb(step: PlanStep, context: HandlerContext) -> StepResult:
    result = fingerprint_with_whatweb(
        str(step.params.get("target", "")),
        mode="http_ip_probe" if step.params.get("target_type") == "ip" else "http_probe",
        host=str(step.params.get("host", "")),
        scheme=str(step.params.get("scheme", "")),
        path=str(step.params.get("path", "")),
        port=str(step.params.get("port", "")),
        timeout_seconds=step.timeout_seconds or 20.0,
        executor=context.command_executor,
    )
    payload = {
        "target": result.target,
        "provider": "whatweb",
        "findings": [
            {
                "url": finding.url,
                "status_code": finding.status_code,
                "title": finding.title,
                "webserver": finding.webserver,
                "technologies": list(finding.technologies),
                "plugins": list(finding.plugins),
            }
            for finding in result.findings
        ],
        "skipped": result.skipped,
        "negative_observation": result.negative_observation,
        "raw_output": result.raw_output,
        "elapsed_seconds": result.elapsed_seconds,
    }
    artifacts = tuple(
        artifact(step, "web.technology", finding.url, {"name": technology}, provider="whatweb", confidence=0.85)
        for finding in result.findings
        for technology in finding.technologies
    )
    return StepResult(step.tool, step.action, result.ok, payload, result.error, artifacts=artifacts)


def execute_katana(step: PlanStep, context: HandlerContext) -> StepResult:
    result = crawl_with_katana(
        str(step.params.get("target", "")),
        host=str(step.params.get("host", "")),
        scheme=str(step.params.get("scheme", "")),
        path=str(step.params.get("path", "")),
        port=str(step.params.get("port", "")),
        timeout_seconds=step.timeout_seconds or 30.0,
        executor=context.command_executor,
    )
    payload = {
        "target": result.target,
        "crawl_url": result.crawl_url,
        "provider": "katana",
        "findings": [
            {
                "url": finding.url,
                "method": finding.method,
                "status_code": finding.status_code,
                "title": finding.title,
                "technologies": list(finding.technologies),
            }
            for finding in result.findings
        ],
        "skipped": result.skipped,
        "negative_observation": result.negative_observation,
        "raw_output": result.raw_output,
        "elapsed_seconds": result.elapsed_seconds,
    }
    artifacts = []
    for finding in result.findings:
        artifacts.append(artifact(step, "web.endpoint", finding.url, {"method": finding.method, "status_code": finding.status_code}, provider="katana", confidence=0.9))
        artifacts.extend(
            artifact(step, "web.technology", finding.url, {"name": technology}, provider="katana", confidence=0.8)
            for technology in finding.technologies
        )
    return StepResult(step.tool, step.action, result.ok, payload, result.error, artifacts=tuple(artifacts))


def _httpx_discovery_endpoints(context: HandlerContext) -> tuple[str, ...]:
    endpoints: set[str] = set()
    for item in context.evidence.find("host.port"):
        if str(item.data.get("state", "")).lower() != "open":
            continue
        if str(item.data.get("protocol", "tcp")).lower() != "tcp":
            continue
        try:
            port = int(item.data.get("port", 0))
        except (TypeError, ValueError):
            continue
        if item.subject and 1 <= port <= 65535:
            endpoints.add(f"{item.subject}:{port}")
    return tuple(sorted(endpoints))


HANDLERS = (
    ("http", execute_http),
    ("httpx", execute_httpx),
    ("fingerprint", execute_fingerprint),
    ("whatweb", execute_whatweb),
    ("katana", execute_katana),
)
