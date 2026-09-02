import io
import unittest
from contextlib import redirect_stdout

from blackline.cli.commands.recon.recon_cmd import render_recon_report
from blackline.core.recon.models import normalize_recon_target
from blackline.core.recon.steps.tls import tls_inspection_step
from blackline.tools.tls.inspector import parse_openssl_certificate_output


class TlsInspectorTests(unittest.TestCase):
    def test_parse_openssl_certificate_output_extracts_certificate_facts(self):
        metadata = parse_openssl_certificate_output(
            "subject=CN = example.com\n"
            "issuer=C = US, O = Example CA, CN = Example Issuer\n"
            "notBefore=Aug 30 12:00:00 2026 GMT\n"
            "notAfter=Sep 30 12:00:00 2027 GMT\n"
            "X509v3 Subject Alternative Name:\n"
            "    DNS:example.com, DNS:www.example.com, IP Address:192.0.2.10\n"
        )

        self.assertEqual(metadata["subject"], "CN = example.com")
        self.assertEqual(metadata["issuer"], "C = US, O = Example CA, CN = Example Issuer")
        self.assertEqual(metadata["sans"], ("DNS:example.com", "DNS:www.example.com", "IP Address:192.0.2.10"))
        self.assertEqual(metadata["not_before"], "2026-08-30T12:00:00+00:00")
        self.assertEqual(metadata["not_after"], "2027-09-30T12:00:00+00:00")

    def test_tls_step_uses_url_port_and_hostname_for_sni(self):
        step = tls_inspection_step(normalize_recon_target("https://Example.com:8443/login"))

        self.assertEqual(step.tool, "tls")
        self.assertEqual(step.inputs["port"], "8443")
        self.assertEqual(step.inputs["server_name"], "example.com")

    def test_tls_step_avoids_sni_for_direct_ip(self):
        step = tls_inspection_step(normalize_recon_target("192.0.2.10"))

        self.assertEqual(step.inputs["port"], "443")
        self.assertEqual(step.inputs["server_name"], "")

    def test_tls_report_uses_dim_provenance_and_curated_facts(self):
        output = io.StringIO()
        with redirect_stdout(output):
            render_recon_report(
                {
                    "tls": {
                        "host": "example.com",
                        "port": 443,
                        "provider": "python ssl",
                        "certificate_parser": "openssl",
                        "protocol": "TLSv1.3",
                        "cipher": "TLS_AES_256_GCM_SHA384",
                        "subject": "CN = example.com",
                        "issuer": "CN = Example CA",
                        "sans": ["DNS:example.com", "DNS:www.example.com"],
                        "not_after": "2027-09-30T12:00:00+00:00",
                        "days_until_expiry": 395,
                        "raw_output": "subject=not rendered",
                    }
                },
                use_color=False,
            )

        text = output.getvalue()
        self.assertIn("tls  (sources: python ssl, openssl)", text)
        self.assertIn("protocol   : TLSv1.3", text)
        self.assertIn("sans       : DNS:example.com, DNS:www.example.com", text)
        self.assertNotIn("subject=not rendered", text)


if __name__ == "__main__":
    unittest.main()
