import json
import unittest
from pathlib import Path
from unittest.mock import patch

from blackline.tools.parsers.sslyze import parse_sslyze_json
from blackline.tools.tls.sslyze import build_sslyze_command, inspect_tls_configuration
from blackline.utils.exec import CommandResult


SSLYZE_OUTPUT = {
    "server_scan_results": [
        {
            "server_location": {"hostname": "example.com", "port": 443},
            "scan_result": {
                "tls_1_2_cipher_suites": {"status": "COMPLETED", "result": {"accepted_cipher_suites": [{"cipher_suite": {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}}]}},
                "tls_1_3_cipher_suites": {"status": "COMPLETED", "result": {"accepted_cipher_suites": [{"cipher_suite": {"name": "TLS_AES_256_GCM_SHA384"}}]}},
                "heartbleed": {"status": "COMPLETED", "result": {"is_vulnerable_to_heartbleed": False}},
                "robot": {"status": "COMPLETED", "result": {"robot_result": {"is_vulnerable_to_robot": True}}},
            },
        }
    ]
}


class SslyzeToolTests(unittest.TestCase):
    def test_parser_extracts_protocols_ciphers_and_explicit_findings(self):
        scans = parse_sslyze_json(json.dumps(SSLYZE_OUTPUT))
        self.assertEqual(scans[0]["protocols"], ("TLS 1.2", "TLS 1.3"))
        self.assertEqual(scans[0]["ciphers"], ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"))
        self.assertEqual(scans[0]["findings"], ("ROBOT vulnerable",))

    def test_adapter_reads_json_file_created_by_sslyze(self):
        def executor(command):
            json_path = Path(next(item for item in command if item.startswith("--json_out=")).split("=", 1)[1])
            json_path.write_text(json.dumps(SSLYZE_OUTPUT), encoding="utf-8")
            return CommandResult(command, 0, "", "", 0.1)

        result = inspect_tls_configuration("example.com", port=443, executor=executor, config={"binary": "sslyze", "flags": ["--quiet"]})
        self.assertTrue(result.ok)
        self.assertEqual(result.scans[0].protocols, ("TLS 1.2", "TLS 1.3"))

    def test_missing_binary_skips_safely(self):
        with patch("blackline.tools.tls.sslyze.which", return_value=None):
            result = inspect_tls_configuration("example.com", config={"binary": "sslyze"})
        self.assertTrue(result.skipped)

    def test_command_uses_explicit_host_port_and_json_file(self):
        command = build_sslyze_command("example.com", port=8443, json_path=Path("/tmp/sslyze.json"), config={"binary": "sslyze", "flags": ["--quiet"]})
        self.assertEqual(command, ("sslyze", "--quiet", "--json_out=/tmp/sslyze.json", "example.com:8443"))


if __name__ == "__main__":
    unittest.main()
