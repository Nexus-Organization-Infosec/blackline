"""Contracts for the optional ProjectDiscovery Katana adapter."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from blackline.tools.http.katana import build_katana_command, build_katana_target, crawl_with_katana
from blackline.tools.parsers.katana import parse_katana_jsonl
from blackline.utils.exec import CommandResult


class KatanaToolTests(unittest.TestCase):
    def test_parser_normalizes_jsonl_request_and_response_fields(self):
        findings = parse_katana_jsonl(
            '\n'.join(
                (
                    '{"request":{"method":"GET","endpoint":"https://example.com/docs"},"response":{"status_code":200,"title":"Docs","technologies":["Next.js"]}}',
                    '{"request":{"method":"GET","endpoint":"https://example.com/docs"},"response":{"status_code":200}}',
                    'not json',
                )
            )
        )

        self.assertEqual(findings, [{"url": "https://example.com/docs", "method": "GET", "status_code": 200, "title": "Docs", "technologies": ("Next.js",)}])

    def test_adapter_uses_explicit_url_and_preserves_findings(self):
        seen: list[tuple[str, ...]] = []

        def executor(command: tuple[str, ...]) -> CommandResult:
            seen.append(command)
            return CommandResult(command, 0, '{"request":{"endpoint":"https://example.com/login"},"response":{"status_code":200}}\n', "", 0.2)

        result = crawl_with_katana(
            "https://example.com/app",
            executor=executor,
            config={"binary": "katana", "flags": ["-jsonl", "-silent"]},
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.crawl_url, "https://example.com/app")
        self.assertEqual(result.findings[0].url, "https://example.com/login")
        self.assertEqual(seen[0], ("katana", "-u", "https://example.com/app", "-jsonl", "-silent"))

    def test_domain_target_gets_a_conventional_https_url(self):
        self.assertEqual(build_katana_target("example.com", host="example.com"), "https://example.com/")

    @patch("blackline.tools.http.katana.which", return_value=None)
    def test_missing_binary_is_a_skipped_optional_observation(self, _which):
        result = crawl_with_katana("example.com", config={"binary": "katana"})

        self.assertTrue(result.skipped)
        self.assertFalse(result.ok)

    def test_command_uses_bounded_configured_flags(self):
        command = build_katana_command(
            "https://example.com",
            config={"flags": ["-jsonl", "-silent", "-d", "2", "-rl", "10"]},
        )

        self.assertEqual(command, ("katana", "-u", "https://example.com", "-jsonl", "-silent", "-d", "2", "-rl", "10"))


if __name__ == "__main__":
    unittest.main()
