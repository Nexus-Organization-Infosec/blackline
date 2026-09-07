import json
import unittest
from pathlib import Path
from unittest.mock import patch

from blackline.tools.http.whatweb import build_whatweb_command, fingerprint_with_whatweb
from blackline.tools.parsers.whatweb import parse_whatweb_json
from blackline.utils.exec import CommandResult


WHATWEB_LOG = [
    {
        "target": "http://10.0.0.174:3000",
        "http_status": 200,
        "plugins": {
            "Title": {"string": ["OWASP Juice Shop"]},
            "HTTPServer": {"string": ["nginx"]},
            "Express": {},
            "Node.js": {},
        },
    },
    {},
]


class WhatWebToolTests(unittest.TestCase):
    def test_parser_normalizes_json_log_and_ignores_empty_trailer(self):
        findings = parse_whatweb_json(json.dumps(WHATWEB_LOG))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "OWASP Juice Shop")
        self.assertEqual(findings[0]["webserver"], "nginx")
        self.assertEqual(findings[0]["technologies"], ("Express", "Node.js"))

    def test_adapter_uses_url_and_reads_whatweb_json_log(self):
        commands = []

        def executor(command):
            commands.append(command)
            log_arg = next(argument for argument in command if argument.startswith("--log-json="))
            Path(log_arg.split("=", 1)[1]).write_text(json.dumps(WHATWEB_LOG), encoding="utf-8")
            return CommandResult(command, 0, "", "", 0.1)

        result = fingerprint_with_whatweb(
            "10.0.0.174",
            mode="http_ip_probe",
            host="10.0.0.174",
            port="3000",
            executor=executor,
            config={"binary": "whatweb", "flags": ["--aggression=1", "--quiet"]},
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.findings[0].technologies, ("Express", "Node.js"))
        self.assertIn("http://10.0.0.174:3000", commands[0])
        self.assertIn("--aggression=1", commands[0])

    def test_missing_binary_skips_without_error(self):
        with patch("blackline.tools.http.whatweb.which", return_value=None):
            result = fingerprint_with_whatweb("example.com", mode="http_probe", config={"binary": "whatweb"})

        self.assertTrue(result.skipped)
        self.assertFalse(result.ok)

    def test_command_writes_json_to_given_path(self):
        command = build_whatweb_command(
            ["https://example.com"],
            log_path=Path("/tmp/blackline-whatweb.json"),
            config={"binary": "whatweb", "flags": ["--quiet"]},
        )
        self.assertEqual(command, ("whatweb", "--quiet", "--log-json=/tmp/blackline-whatweb.json", "https://example.com"))


if __name__ == "__main__":
    unittest.main()
