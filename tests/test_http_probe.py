import unittest

from blackline.core.recon.models import ReconTarget
from blackline.core.recon.steps.http import execute_http_step
from blackline.tools.http import client
from blackline.tools.parsers.curl import parse_curl_probe_output


class HttpProbeTests(unittest.TestCase):
    def test_probe_http_for_domain_uses_https_then_http(self):
        calls: list[str] = []

        def fetcher(url: str, headers: dict[str, str], timeout: float) -> dict[str, object]:
            calls.append(url)
            if url.startswith("https://"):
                return {
                    "url": url,
                    "status_code": 200,
                    "title": "Example Domain",
                    "headers": {"server": "example"},
                    "ok": True,
                }
            return {
                "url": url,
                "status_code": 301,
                "redirect_to": "https://example.com",
                "headers": {"location": "https://example.com"},
                "ok": True,
            }

        result = client.probe_http(
            "example.com",
            mode="http_probe",
            host="example.com",
            fetcher=fetcher,
        )

        self.assertTrue(result.ok)
        self.assertEqual(calls, ["https://example.com", "http://example.com"])
        self.assertEqual(result.findings[0].status_code, 200)
        self.assertEqual(result.findings[0].title, "Example Domain")
        self.assertEqual(result.findings[1].redirect_to, "https://example.com")

    def test_probe_http_for_url_uses_explicit_scheme_and_path(self):
        calls: list[str] = []

        def fetcher(url: str, headers: dict[str, str], timeout: float) -> dict[str, object]:
            calls.append(url)
            return {"url": url, "status_code": 200, "title": "Login", "ok": True}

        result = client.probe_http(
            "https://example.com/login",
            mode="http_probe",
            host="example.com",
            scheme="https",
            path="/login",
            fetcher=fetcher,
        )

        self.assertTrue(result.ok)
        self.assertEqual(calls, ["https://example.com/login"])
        self.assertEqual(result.findings[0].title, "Login")

    def test_execute_http_step_uses_client(self):
        original_probe_http = execute_http_step.__globals__["probe_http"]

        class FakeResult:
            ok = True
            target = "10.0.0.1"
            mode = "http_ip_probe"
            provider = "custom"
            error = ""
            elapsed_seconds = 0.2
            findings = []

        execute_http_step.__globals__["probe_http"] = lambda *args, **kwargs: FakeResult()
        try:
            result = execute_http_step(
                ReconTarget(raw="10.0.0.1", target_type="ip", host="10.0.0.1"),
                mode="http_ip_probe",
            )
        finally:
            execute_http_step.__globals__["probe_http"] = original_probe_http

        self.assertTrue(result.ok)
        self.assertEqual(result.mode, "http_ip_probe")

    def test_parse_curl_probe_output_extracts_status_title_and_redirect(self):
        parsed = parse_curl_probe_output(
            "http://example.com",
            (
                "HTTP/1.1 301 Moved Permanently\r\n"
                "Location: https://example.com\r\n\r\n"
                "HTTP/2 200\r\n"
                "Content-Type: text/html\r\n\r\n"
                "<html><title>Example Domain</title></html>"
            ),
            returncode=0,
        )

        self.assertEqual(parsed["status_code"], 200)
        self.assertEqual(parsed["title"], "Example Domain")


if __name__ == "__main__":
    unittest.main()
