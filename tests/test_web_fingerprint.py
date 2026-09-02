import io
import unittest
from contextlib import redirect_stdout

from blackline.cli.commands.recon.recon_cmd import render_recon_report
from blackline.tools.http.fingerprint import fingerprint_http


class WebFingerprintTests(unittest.TestCase):
    def test_fingerprint_detects_technologies_from_normal_page_evidence(self):
        result = fingerprint_http(
            "example.com",
            mode="http_probe",
            host="example.com",
            fetcher=lambda url, headers, timeout: {
                "status_code": 200,
                "headers": {
                    "server": "cloudflare",
                    "x-powered-by": "Next.js",
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "set-cookie": "session=abc; Secure, theme=dark; Secure",
                },
                "body": '<script src="/_next/static/app.js"></script><div data-reactroot></div>',
            },
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.server, "cloudflare")
        self.assertEqual(result.framework, "Next.js")
        self.assertEqual(result.javascript, "React")
        self.assertEqual(result.security_headers, ("HSTS", "CSP"))
        self.assertEqual(result.cookies, ("session", "theme"))
        self.assertEqual(result.confidence, "high")

    def test_fingerprint_skips_when_http_is_closed(self):
        result = fingerprint_http(
            "10.0.0.1",
            mode="http_ip_probe",
            host="10.0.0.1",
            fetcher=lambda url, headers, timeout: {"error": "[Errno 61] Connection refused"},
        )

        self.assertTrue(result.ok)
        self.assertTrue(result.skipped)
        self.assertEqual(result.error, "")

    def test_fingerprint_report_keeps_cookie_values_out_of_terminal(self):
        output = io.StringIO()
        with redirect_stdout(output):
            render_recon_report(
                {
                    "fingerprint": {
                        "provider": "urllib",
                        "server": "cloudflare",
                        "framework": "Next.js",
                        "cms": "unknown",
                        "javascript": "React",
                        "security_headers": ["HSTS", "CSP"],
                        "cookies": ["session"],
                        "confidence": "high",
                    }
                },
                use_color=False,
            )

        text = output.getvalue()
        self.assertIn("web fingerprint  (source: urllib)", text)
        self.assertIn("framework  : Next.js", text)
        self.assertIn("headers    : HSTS, CSP", text)
        self.assertNotIn("session=", text)


if __name__ == "__main__":
    unittest.main()
