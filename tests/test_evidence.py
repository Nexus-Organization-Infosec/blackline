import io
import unittest
from contextlib import redirect_stdout

from blackline.cli.commands.recon.recon_cmd import render_recon_report
from blackline.core.recon.evidence import build_evidence_graph


class EvidenceGraphTests(unittest.TestCase):
    def setUp(self):
        self.payloads = {
            "dns": {
                "provider": "dnspython",
                "records": {"A": ["172.66.157.115"], "AAAA": []},
            },
            "ipintel": {
                "provider": "yougotmapped",
                "lookup_ip": "172.66.157.115",
                "asn": "AS13335",
                "org": "Cloudflare, Inc.",
            },
            "rdap": {
                "provider": "rdap.org",
                "domain": "owasp.org",
                "registrar": "Example Registrar",
                "address": "172.66.157.115",
                "organization": "Cloudflare, Inc.",
                "asn": "AS13335",
            },
            "fingerprint": {"provider": "urllib", "server": "cloudflare", "framework": "Next.js"},
            "tls": {
                "provider": "python ssl",
                "certificate_parser": "openssl",
                "sans": ["DNS:owasp.org", "DNS:www.owasp.org"],
            },
        }

    def test_graph_merges_sources_for_the_same_relationship(self):
        graph = build_evidence_graph("owasp.org", self.payloads)

        address_claim = next(claim for claim in graph.claims if claim.predicate == "resolves_to" and claim.value == "172.66.157.115")
        self.assertEqual(address_claim.sources, ("dnspython", "rdap.org", "yougotmapped"))
        self.assertEqual(graph.values("announced_by"), ("AS13335",))
        self.assertEqual(graph.values("presents_tls_name"), ("owasp.org", "www.owasp.org"))

    def test_correlation_report_renders_cross_tool_joins(self):
        graph = build_evidence_graph("owasp.org", self.payloads)
        output = io.StringIO()
        with redirect_stdout(output):
            render_recon_report({"correlation": graph.to_dict()}, use_color=False)

        text = output.getvalue()
        self.assertIn("correlation  (sources: dnspython, rdap.org, yougotmapped, urllib, python ssl, openssl)", text)
        self.assertIn("addresses  : 172.66.157.115", text)
        self.assertIn("ownership  : Cloudflare, Inc.", text)
        self.assertIn("web edge   : cloudflare", text)
        self.assertIn("tls names  : owasp.org, www.owasp.org", text)


if __name__ == "__main__":
    unittest.main()
