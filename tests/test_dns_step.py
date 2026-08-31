import unittest

from blackline.core.recon.models import ReconTarget
from blackline.core.recon.steps.dns import execute_dns_step
from blackline.tools.dns import resolver


class DnsStepTests(unittest.TestCase):
    def test_resolve_dns_with_custom_provider_returns_structured_records(self):
        requested: list[str] = []

        def provider(host, record_types):
            requested.extend(record_types)
            return {
                "A": ["93.184.216.34"],
                "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
                "CNAME": [],
                "MX": [],
                "NS": ["a.iana-servers.net", "b.iana-servers.net"],
                "TXT": ["v=spf1 -all"],
                "SOA": ["a.iana-servers.net hostmaster.iana.org 1 2 3 4 5"],
                "CAA": ["0 issue letsencrypt.org"],
                "SRV": [],
            }

        lookup = resolver.resolve_dns(
            "example.com",
            provider=provider,
        )

        self.assertTrue(lookup.ok)
        self.assertEqual(lookup.host, "example.com")
        self.assertEqual(lookup.records["A"], ["93.184.216.34"])
        self.assertEqual(lookup.records["NS"], ["a.iana-servers.net", "b.iana-servers.net"])
        self.assertEqual(lookup.resolved_ips, ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"])
        self.assertEqual(lookup.outcome, "answer")
        self.assertEqual(
            requested,
            ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV"],
        )

    def test_resolve_dns_reports_no_data_when_provider_returns_no_records(self):
        lookup = resolver.resolve_dns("example.com", provider=lambda host, record_types: {})

        self.assertFalse(lookup.ok)
        self.assertEqual(lookup.outcome, "no_data")
        self.assertEqual(set(lookup.records), set(resolver.DEFAULT_RECORD_TYPES))

    def test_execute_dns_step_uses_resolver(self):
        original_resolve_dns = execute_dns_step.__globals__["resolve_dns"]

        execute_dns_step.__globals__["resolve_dns"] = lambda host: resolver.DnsLookupResult(
            ok=True,
            host=host,
            records={"A": ["93.184.216.34"], "AAAA": [], "MX": [], "NS": []},
            resolved_ips=["93.184.216.34"],
            provider="custom",
        )
        try:
            lookup = execute_dns_step(ReconTarget(raw="example.com", target_type="domain", host="example.com"))
        finally:
            execute_dns_step.__globals__["resolve_dns"] = original_resolve_dns

        self.assertTrue(lookup.ok)
        self.assertEqual(lookup.records["A"], ["93.184.216.34"])

    def test_resolve_dns_fails_cleanly_for_missing_host(self):
        lookup = resolver.resolve_dns("")

        self.assertFalse(lookup.ok)
        self.assertEqual(lookup.error, "missing dns host")


if __name__ == "__main__":
    unittest.main()
