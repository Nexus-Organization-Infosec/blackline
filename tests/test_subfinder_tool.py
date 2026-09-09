import unittest
from unittest.mock import patch

from blackline.tools.dns.subfinder import build_subfinder_command, enumerate_subdomains
from blackline.tools.parsers.subfinder import parse_subfinder_jsonl
from blackline.utils.exec import CommandResult


class SubfinderToolTests(unittest.TestCase):
    def test_parser_keeps_in_scope_hosts_and_sources(self):
        findings = parse_subfinder_jsonl(
            '\n'.join(
                (
                    '{"host":"api.example.com","sources":["crtsh","alienvault"]}',
                    '{"host":"example.com","source":"hackertarget"}',
                    '{"host":"not-example.com","sources":["crtsh"]}',
                )
            ),
            domain="example.com",
        )

        self.assertEqual(
            findings,
            [
                {"host": "api.example.com", "sources": ("crtsh", "alienvault")},
                {"host": "example.com", "sources": ("hackertarget",)},
            ],
        )

    def test_command_requests_jsonl_sources_and_silent_output(self):
        self.assertEqual(
            build_subfinder_command("example.com", config={"flags": ["-oJ", "-cs", "-silent"]}),
            ("subfinder", "-d", "example.com", "-oJ", "-cs", "-silent"),
        )

    def test_adapter_returns_normalized_findings(self):
        result = enumerate_subdomains(
            "example.com",
            executor=lambda args: CommandResult(
                args=args,
                returncode=0,
                stdout='{"host":"api.example.com","sources":["crtsh"]}\n',
                stderr="",
                elapsed_seconds=0.2,
            ),
        )

        self.assertTrue(result.ok)
        self.assertFalse(result.negative_observation)
        self.assertEqual(result.subdomains[0].host, "api.example.com")
        self.assertEqual(result.subdomains[0].sources, ("crtsh",))

    @patch("blackline.tools.dns.subfinder.which", return_value=None)
    def test_missing_binary_is_a_graceful_skip(self, _which):
        result = enumerate_subdomains("example.com")

        self.assertTrue(result.skipped)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "subfinder unavailable")


if __name__ == "__main__":
    unittest.main()
