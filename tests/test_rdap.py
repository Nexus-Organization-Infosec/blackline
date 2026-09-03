import io
import unittest
from contextlib import redirect_stdout

from blackline.cli.commands.recon.recon_cmd import render_recon_report
from blackline.tools.intel.rdap import resolve_rdap
from tests.fixture_loader import read_json


class RdapTests(unittest.TestCase):
    def test_rdap_normalizes_registration_and_network_ownership(self):
        def fetcher(url: str, timeout: float):
            if "/domain/" in url:
                return {"status_code": 200, "data": read_json("rdap", "owasp.org.json")}
            return {"status_code": 200, "data": read_json("rdap", "172.66.157.115.json")}

        result = resolve_rdap(domain="owasp.org", address="172.66.157.115", fetcher=fetcher)

        self.assertTrue(result.ok)
        self.assertEqual(result.registrar, "Example Registrar")
        self.assertEqual(result.created, "2001-09-27T00:00:00Z")
        self.assertEqual(result.organization, "Cloudflare, Inc.")
        self.assertEqual(result.asn, "AS13335")
        self.assertIn("172.66.157.0", result.network)

    def test_rdap_treats_not_found_as_successful_absence(self):
        result = resolve_rdap(
            domain="example.invalid",
            fetcher=lambda url, timeout: {"status_code": 404, "data": {}},
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.error, "")
        self.assertEqual(result.domain, "example.invalid")

    def test_rdap_report_renders_registration_and_network_together(self):
        output = io.StringIO()
        with redirect_stdout(output):
            render_recon_report(
                {
                    "rdap": {
                        "provider": "rdap.org",
                        "domain": "owasp.org",
                        "registrar": "Example Registrar",
                        "created": "2001-09-27T00:00:00Z",
                        "expires": "2030-09-27T00:00:00Z",
                        "status": ["active"],
                        "address": "172.66.157.115",
                        "network": "CLOUDFLARENET (172.66.157.0 – 172.66.157.255)",
                        "organization": "Cloudflare, Inc.",
                        "asn": "AS13335",
                    }
                },
                use_color=False,
            )

        text = output.getvalue()
        self.assertIn("registration  (source: rdap.org)", text)
        self.assertIn("network ownership  (source: rdap.org)", text)
        self.assertIn("organization: Cloudflare, Inc.", text)
        self.assertIn("asn        : AS13335", text)


if __name__ == "__main__":
    unittest.main()
