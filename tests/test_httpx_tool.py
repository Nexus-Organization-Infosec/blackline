"""Contracts for the optional ProjectDiscovery httpx adapter."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from blackline.tools.http.httpx import (
    build_httpx_command,
    discover_http_services,
    probe_httpx,
    projectdiscovery_httpx_available,
    resolve_projectdiscovery_httpx,
)
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
        with (
            patch("blackline.tools.http.httpx.which", return_value=None),
            patch("blackline.tools.http.httpx.os.get_exec_path", return_value=()),
        ):
            result = probe_httpx("example.com", mode="http_probe", config={"binary": "httpx"})

        self.assertTrue(result.skipped)
        self.assertFalse(result.ok)

    @patch("blackline.tools.http.httpx.run_command")
    @patch("blackline.tools.http.httpx.which", return_value="/usr/local/bin/httpx")
    def test_python_httpx_command_is_rejected(self, _which, run_command):
        run_command.return_value = CommandResult(("httpx", "-version"), 2, "", "Usage: httpx [OPTIONS] URL", 0.01)

        available, message = projectdiscovery_httpx_available()

        self.assertFalse(available)
        self.assertIn("not the ProjectDiscovery scanner", message)

    @patch("blackline.tools.http.httpx.run_command")
    @patch("blackline.tools.http.httpx.which", return_value="/usr/local/bin/httpx")
    def test_projectdiscovery_httpx_version_is_accepted(self, _which, run_command):
        run_command.return_value = CommandResult(("httpx", "-version"), 0, "[INF] Current Version: v1.7.0", "", 0.01)

        available, message = projectdiscovery_httpx_available()

        self.assertTrue(available)
        self.assertEqual(message, "")

    @patch("blackline.tools.http.httpx.os.get_exec_path", return_value=("/python", "/projectdiscovery"))
    @patch("blackline.tools.http.httpx.Path.is_file", return_value=True)
    @patch("blackline.tools.http.httpx.os.access", return_value=True)
    @patch("blackline.tools.http.httpx.run_command")
    @patch("blackline.tools.http.httpx.which", return_value="/python/httpx")
    def test_resolver_skips_python_httpx_and_selects_projectdiscovery_binary(self, _which, run_command, _access, _is_file, _paths):
        run_command.side_effect = (
            CommandResult(("/python/httpx", "-version"), 2, "", "Usage: httpx [OPTIONS] URL", 0.01),
            CommandResult(("/projectdiscovery/httpx", "-version"), 0, "[INF] Current Version: v1.12.0", "", 0.01),
        )

        binary, message = resolve_projectdiscovery_httpx()

        self.assertEqual(binary, "/projectdiscovery/httpx")
        self.assertEqual(message, "")

    def test_discovery_passes_host_and_port_without_assuming_a_scheme(self):
        seen: list[tuple[str, ...]] = []

        def fake_executor(command: tuple[str, ...]) -> CommandResult:
            seen.append(command)
            return CommandResult(command, 0, '{"url":"https://10.0.0.174:3000","status_code":200,"tls":{"protocol":"tls13"}}\n', "", 0.1)

        result = discover_http_services(("10.0.0.174:3000", "10.0.0.174:9000"), executor=fake_executor)

        self.assertTrue(result.ok)
        self.assertEqual(result.findings[0].url, "https://10.0.0.174:3000")
        self.assertIn("10.0.0.174:3000", seen[0])
        self.assertNotIn("http://10.0.0.174:3000", seen[0])
        self.assertNotIn("https://10.0.0.174:3000", seen[0])

    def test_command_includes_configured_metadata_probes(self):
        command = build_httpx_command(
            ["https://example.com"],
            config={"flags": ["-json", "-sc", "-title", "-location", "-td", "-tls-grab", "-silent"]},
        )

        self.assertEqual(command[:3], ("httpx", "-u", "https://example.com"))
        self.assertEqual(command[-2:], ("-tls-grab", "-silent"))
