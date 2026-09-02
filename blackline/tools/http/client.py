"""HTTP client tool wrapper."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from blackline.tools.http.curl_probe import probe_with_curl
from blackline.utils.exec import CommandResult

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

FetchResponse = Callable[[str, dict[str, str], float], dict[str, object]]


@dataclass(frozen=True, slots=True)
class HttpProbeFinding:
    """One HTTP probe finding."""

    url: str
    status_code: int | None = None
    title: str = ""
    redirect_to: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    ok: bool = False
    error: str = ""


@dataclass(frozen=True, slots=True)
class HttpProbeResult:
    """Structured HTTP probing result."""

    ok: bool
    target: str
    mode: str
    findings: list[HttpProbeFinding] = field(default_factory=list)
    provider: str = ""
    error: str = ""
    elapsed_seconds: float = 0.0


def probe_http(
    target: str,
    *,
    mode: str,
    host: str = "",
    scheme: str = "",
    path: str = "",
    port: str = "",
    host_header: str = "",
    timeout: float = 10.0,
    fetcher: FetchResponse | None = None,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
) -> HttpProbeResult:
    """Probe one recon HTTP target with a curated set of URLs."""
    target = target.strip()
    host = (host or target).strip()
    urls = build_http_probe_urls(mode=mode, host=host, scheme=scheme, path=path, port=port)
    if not urls:
        return HttpProbeResult(ok=False, target=target, mode=mode, error="missing http target")

    findings: list[HttpProbeFinding] = []
    started = time.perf_counter()
    provider = "urllib"
    for url in urls:
        headers = {"User-Agent": "blackline/0.1"}
        if host_header:
            headers["Host"] = host_header
        if fetcher is not None:
            finding = _finding_from_mapping(url, fetcher(url, headers, timeout))
            findings.append(finding)
            continue
        try:
            finding = _fetch_with_urllib(url, headers=headers, timeout=timeout)
            findings.append(finding)
        except Exception:
            curl_raw = probe_with_curl(
                url,
                host_header=host_header,
                timeout=timeout,
                executor=command_executor,
            )
            curl_finding = _finding_from_mapping(url, curl_raw)
            provider = "curl" if curl_finding.status_code is not None or curl_finding.error else provider
            findings.append(curl_finding)

    elapsed_seconds = time.perf_counter() - started
    # A refused connection is a valid negative observation: the probe reached
    # the target and established that no HTTP service is accepting connections.
    # It should not make the surrounding recon operation look like it failed.
    ok = any(finding.ok for finding in findings) or _all_findings_closed(findings)
    error = "" if ok else _first_http_error(findings)
    return HttpProbeResult(
        ok=ok,
        target=target,
        mode=mode,
        findings=findings,
        provider=provider,
        error=error,
        elapsed_seconds=elapsed_seconds,
    )


def build_http_probe_urls(*, mode: str, host: str, scheme: str, path: str, port: str) -> list[str]:
    if not host:
        return []

    normalized_path = path or ""
    if normalized_path and not normalized_path.startswith(("/", "?", "#")):
        normalized_path = f"/{normalized_path}"
    suffix = f":{port}" if port else ""

    if mode == "http_probe":
        if scheme:
            return [f"{scheme}://{host}{suffix}{normalized_path}"]
        return [f"https://{host}{suffix}{normalized_path}", f"http://{host}{suffix}{normalized_path}"]

    if mode == "http_ip_probe":
        return [f"http://{host}{suffix}", f"https://{host}{suffix}"]

    if mode == "http_vhost_probe":
        return [f"http://{host}{suffix}{normalized_path}", f"https://{host}{suffix}{normalized_path}"]

    return []


def _fetch_with_urllib(url: str, *, headers: dict[str, str], timeout: float) -> HttpProbeFinding:
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(16384).decode("utf-8", errors="replace")
            final_url = response.geturl()
            return HttpProbeFinding(
                url=url,
                status_code=response.getcode(),
                title=_extract_title(body),
                redirect_to=final_url if final_url != url else "",
                headers={key.lower(): value for key, value in response.headers.items()},
                ok=True,
            )
    except HTTPError as exc:
        body = exc.read(16384).decode("utf-8", errors="replace")
        return HttpProbeFinding(
            url=url,
            status_code=exc.code,
            title=_extract_title(body),
            redirect_to=exc.geturl() if exc.geturl() != url else "",
            headers={key.lower(): value for key, value in exc.headers.items()},
            ok=False,
            error=str(exc),
        )
    except URLError as exc:
        return HttpProbeFinding(url=url, ok=False, error=str(exc.reason or exc))


def _extract_title(body: str) -> str:
    match = _TITLE_RE.search(body)
    if not match:
        return ""
    title = " ".join(match.group(1).split())
    return title.strip()


def _finding_from_mapping(url: str, raw: dict[str, object]) -> HttpProbeFinding:
    headers = raw.get("headers", {})
    if not isinstance(headers, dict):
        headers = {}
    return HttpProbeFinding(
        url=str(raw.get("url", url)),
        status_code=int(raw["status_code"]) if raw.get("status_code") is not None else None,
        title=str(raw.get("title", "")),
        redirect_to=str(raw.get("redirect_to", "")),
        headers={str(key).lower(): str(value) for key, value in headers.items()},
        ok=bool(raw.get("ok", raw.get("status_code") is not None and int(raw.get("status_code", 0)) < 400)),
        error=str(raw.get("error", "")),
    )


def _first_http_error(findings: list[HttpProbeFinding]) -> str:
    for finding in findings:
        if finding.error:
            return finding.error
    return "http probe failed"


def _all_findings_closed(findings: list[HttpProbeFinding]) -> bool:
    """Return True when every completed probe observed a refused connection."""
    return bool(findings) and all(
        finding.status_code is None and _is_connection_refused(finding.error)
        for finding in findings
    )


def _is_connection_refused(error: str) -> bool:
    return "connection refused" in error.lower()
