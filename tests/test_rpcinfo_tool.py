import unittest
from unittest.mock import patch

from blackline.tools.network.rpcinfo import build_rpcinfo_command, query_rpcinfo
from blackline.tools.parsers.rpcinfo import parse_rpcinfo_table
from blackline.utils.exec import CommandResult


RPCINFO_OUTPUT = """   program vers proto   port  service
    100000    4   tcp    111  rpcbind
    100000    3   udp    111  rpcbind
    100005    1   udp  40487  mountd
"""


class RpcInfoToolTests(unittest.TestCase):
    def test_parser_extracts_registered_programs(self):
        records = parse_rpcinfo_table(RPCINFO_OUTPUT)

        self.assertEqual(len(records), 3)
        self.assertEqual(records[0], {"program": 100000, "version": 4, "protocol": "tcp", "port": 111, "service": "rpcbind"})
        self.assertEqual(records[2]["service"], "mountd")

    def test_adapter_returns_structured_registrations(self):
        result = query_rpcinfo(
            "10.0.0.174",
            executor=lambda args: CommandResult(args, 0, RPCINFO_OUTPUT, "", 0.2),
            config={"binary": "rpcinfo", "flags": ["-p"]},
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.registrations[2].port, 40487)
        self.assertEqual(result.registrations[2].service, "mountd")

    def test_missing_binary_skips_safely(self):
        with patch("blackline.tools.network.rpcinfo.which", return_value=None):
            result = query_rpcinfo("10.0.0.174", config={"binary": "rpcinfo"})

        self.assertTrue(result.skipped)
        self.assertFalse(result.ok)

    def test_command_is_a_bounded_portmapper_listing(self):
        self.assertEqual(build_rpcinfo_command("10.0.0.174", config={"binary": "rpcinfo", "flags": ["-p"]}), ("rpcinfo", "-p", "10.0.0.174"))


if __name__ == "__main__":
    unittest.main()
