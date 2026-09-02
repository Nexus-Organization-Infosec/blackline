"""Small, evidence-based HTTP technology fingerprinting adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from blackline.tools.http.client import build_http_probe_urls

FetchResponse = Callable[[str, dict[str, str], float], dict[str, object]]


@dataclass(frozen=True, slots=True)
class WebFingerprintResult:
    """Technologies observed from ordinary HTTP response evidence."""

    ok: bool
    target: str
    server: str = "unknown"
    framework: str = "unknown"
    cms: str = "unknown"
    javascript: str = "unknown"
    security_headers: tuple[str, ...] = field(default_factory=tuple)
    cookies: tuple[str, ...] = field(default_factory=tuple)
    confidence: str = "low"
    evidence: tuple[str, ...] = field(default_factory=tuple)
    provider: str = "urllib"
    skipped: bool = False
    warnings: tuple[str, ...] = field(default_factory=tuple)
    error: str = ""
    elapsed_seconds: float = 0.0


def fingerprint_http(
    target: str,
    *,
    mode: str,
    host: str = "",
    scheme: str = "",
    path: str = "",
    port: str = "",
    timeout: float = 10.0,
    fetcher: FetchResponse | None = None,
) -> WebFingerprintResult:
    """Fingerprint normal HTTP responses without active content discovery."""
    target = target.strip()
    urls = build_http_probe_urls(mode=mode, host=(host or target).strip(), scheme=scheme, path=path, port=port)
    if not urls:
        return WebFingerprintResult(False, target, error="missing http target")

    started = time.perf_counter()
    observations: list[dict[str, object]] = []
    errors: list[str] = []
    for url in urls:
        headers = {"User-Agent": "blackline/0.1"}
        if fetcher is not None:
            response = fetcher(url, headers, timeout)
        else:
            response = _fetch_page(url, headers=headers, timeout=timeout)
        if response.get("status_code") is None:
            errors.append(str(response.get("error", "http request failed")))
        else:
            observations.append(response)

    elapsed = time.perf_counter() - started
    if not observations:
        if errors and all(_is_connection_refused(message) for message in errors):
            return WebFingerprintResult(True, target, skipped=True, elapsed_seconds=elapsed)
        return WebFingerprintResult(False, target, error=errors[0] if errors else "http fingerprint failed", elapsed_seconds=elapsed)

    headers = _combined_headers(observations)
    body = "\n".join(str(item.get("body", "")) for item in observations)
    server, server_evidence = _detect_server(headers)
    framework, framework_evidence = _detect_framework(headers, body)
    cms, cms_evidence = _detect_cms(headers, body)
    javascript, javascript_evidence = _detect_javascript(body)
    security_headers = _security_headers(headers)
    cookies = _cookie_names(headers)
    evidence = tuple(server_evidence + framework_evidence + cms_evidence + javascript_evidence)
    warnings = ("some web endpoints were unavailable",) if errors else ()
    return WebFingerprintResult(
        True,
        target,
        server=server,
        framework=framework,
        cms=cms,
        javascript=javascript,
        security_headers=security_headers,
        cookies=cookies,
        confidence=_confidence(evidence, security_headers, cookies),
        evidence=evidence,
        warnings=warnings,
        elapsed_seconds=elapsed,
    )


def _fetch_page(url: str, *, headers: dict[str, str], timeout: float) -> dict[str, object]:
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            return {
                "status_code": response.getcode(),
                "headers": {key.lower(): value for key, value in response.headers.items()},
                "body": response.read(65536).decode("utf-8", errors="replace"),
            }
    except HTTPError as exc:
        return {
            "status_code": exc.code,
            "headers": {key.lower(): value for key, value in exc.headers.items()},
            "body": exc.read(65536).decode("utf-8", errors="replace"),
        }
    except URLError as exc:
        return {"error": str(exc.reason or exc)}


def _combined_headers(observations: list[dict[str, object]]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for observation in observations:
        raw_headers = observation.get("headers", {})
        if isinstance(raw_headers, dict):
            headers.update({str(key).lower(): str(value) for key, value in raw_headers.items()})
    return headers


def _detect_server(headers: dict[str, str]) -> tuple[str, list[str]]:
    server = headers.get("server", "").strip()
    if not server:
        return "unknown", []
    normalized = server.lower()
    for label, marker in (("cloudflare", "cloudflare"), ("nginx", "nginx"), ("Apache", "apache"), ("Caddy", "caddy"), ("Microsoft-IIS", "microsoft-iis"), ("LiteSpeed", "litespeed")):
        if marker in normalized:
            return label, ["server header"]
    return server, ["server header"]


def _detect_framework(headers: dict[str, str], body: str) -> tuple[str, list[str]]:
    powered_by = headers.get("x-powered-by", "").lower()
    checks = (("Next.js", ("next.js" in powered_by, "__next_data__" in body.lower(), "/_next/" in body.lower())), ("Express", ("express" in powered_by,)), ("Django", ("django" in powered_by,)), ("Laravel", ("laravel" in powered_by,)))
    for label, matches in checks:
        if any(matches):
            return label, [f"{label} marker"]
    return "unknown", []


def _detect_cms(headers: dict[str, str], body: str) -> tuple[str, list[str]]:
    haystack = f"{headers.get('x-generator', '')}\n{body}".lower()
    for label, markers in (("WordPress", ("wp-content/", "wp-includes/", "wordpress")), ("Drupal", ("drupal-settings-json", "drupalsettings", "x-generator: drupal")), ("Joomla", ("/media/system/js/", "joomla"))):
        if any(marker in haystack for marker in markers):
            return label, [f"{label} marker"]
    return "unknown", []


def _detect_javascript(body: str) -> tuple[str, list[str]]:
    lowered = body.lower()
    for label, markers in (("React", ("data-reactroot", "react-dom", "react.production")), ("Vue", ("data-v-", "vue.global", "vue.runtime")), ("Angular", ("ng-version", "angular.js", "angular.min.js")), ("Svelte", ("svelte",))):
        if any(marker in lowered for marker in markers):
            return label, [f"{label} marker"]
    return "unknown", []


def _security_headers(headers: dict[str, str]) -> tuple[str, ...]:
    mapping = (("strict-transport-security", "HSTS"), ("content-security-policy", "CSP"), ("x-frame-options", "X-Frame-Options"), ("permissions-policy", "Permissions-Policy"), ("referrer-policy", "Referrer-Policy"))
    return tuple(label for name, label in mapping if headers.get(name))


def _cookie_names(headers: dict[str, str]) -> tuple[str, ...]:
    raw = headers.get("set-cookie", "")
    names = [match.group(1) for match in re.finditer(r"(?:^|,\s*)([^=;,\s]+)=", raw)]
    return tuple(dict.fromkeys(names))


def _confidence(evidence: tuple[str, ...], security_headers: tuple[str, ...], cookies: tuple[str, ...]) -> str:
    signals = len(evidence) + bool(security_headers) + bool(cookies)
    return "high" if signals >= 3 else "medium" if signals >= 1 else "low"


def _is_connection_refused(error: str) -> bool:
    return "connection refused" in error.lower()
