"""Contracts for the optional ProjectDiscovery httpx adapter."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from blackline.tools.http.httpx import build_httpx_command, probe_httpx
from blackline.tools.parsers.httpx import parse_httpx_jsonl
from blackline.utils.exec import CommandResult


class HttpxToolTests(unittest.TestCase):
    def test_jsonl_parser_preserves_web_and_tls_metadata(self):
        findings = parse_httpx_jsonl(
            '{"url":"http://10.0.0.174:3000","status_code":200,"title":"Juice Shop","location":"","technologies":["Express","Node.js"],"webserver":"Express","tls":{"protocol":"tls13"}}\n'
        )

        self.assertEqual(findings[0]["status_code"], 200)
        self.assertEqual(findings[0]["technologies"], ("Express", "Node.js"))
        self.assertEqual(findings[0]["tls"], {"protocol": "tls13"})

    def test_probe_confirms_http_on_an_explicit_nonstandard_port(self):
        seen: list[tuple[str, ...]] = []

        def fake_executor(command: tuple[str, ...]) -> CommandResult:
            seen.append(command)
            return CommandResult(
                command,
                0,
                '{"url":"http://10.0.0.174:3000","status_code":200,"title":"Juice Shop","technologies":["Express"]}\n',
                "",
                0.2,
            )

        result = probe_httpx(
            "10.0.0.174",
            mode="http_ip_probe",
            host="10.0.0.174",
            scheme="http",
            port="3000",
            executor=fake_executor,
            config={"binary": "httpx", "flags": ["-json", "-sc", "-title", "-td"]},
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.findings[0].url, "http://10.0.0.174:3000")
        self.assertIn("-u", seen[0])
        self.assertIn("http://10.0.0.174:3000", seen[0])

    def test_missing_binary_is_a_skipped_optional_observation(self):
        with patch("blackline.tools.http.httpx.which", return_value=None):
            result = probe_httpx("example.com", mode="http_probe", config={"binary": "httpx"})

        self.assertTrue(result.skipped)
        self.assertFalse(result.ok)

    def test_command_includes_configured_metadata_probes(self):
        command = build_httpx_command(
            ["https://example.com"],
            config={"flags": ["-json", "-sc", "-title", "-location", "-td", "-tls-grab", "-silent"]},
        )

        self.assertEqual(command[:3], ("httpx", "-u", "https://example.com"))
        self.assertEqual(command[-2:], ("-tls-grab", "-silent"))
