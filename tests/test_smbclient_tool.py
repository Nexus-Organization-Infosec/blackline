"""Contracts for bounded, anonymous smbclient enumeration."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from blackline.tools.network.smbclient import build_smbclient_command, enumerate_smb_shares
from blackline.tools.parsers.smbclient import parse_smbclient_grepable
from blackline.utils.exec import CommandResult


SMBCLIENT_OUTPUT = """Domain=[WORKGROUP] OS=[Windows 10] Server=[Samba]
Disk|public|Public files
IPC|IPC$|IPC Service (Samba)
Disk|public|Public files
"""


class SmbClientToolTests(unittest.TestCase):
    def test_parser_extracts_unique_share_metadata(self):
        self.assertEqual(
            parse_smbclient_grepable(SMBCLIENT_OUTPUT),
            [
                {"name": "public", "type": "disk", "comment": "Public files"},
                {"name": "IPC$", "type": "ipc", "comment": "IPC Service (Samba)"},
            ],
        )

    def test_adapter_uses_anonymous_listing_without_accessing_shares(self):
        result = enumerate_smb_shares(
            "10.0.0.5",
            executor=lambda args: CommandResult(args, 0, SMBCLIENT_OUTPUT, "", 0.1),
            config={"binary": "smbclient", "flags": ["-N", "-g"]},
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.shares[0].name, "public")
        self.assertFalse(result.negative_observation)

    def test_access_denied_is_a_warning_not_a_claim_that_smb_is_absent(self):
        result = enumerate_smb_shares(
            "10.0.0.5",
            executor=lambda args: CommandResult(args, 1, "", "NT_STATUS_ACCESS_DENIED", 0.1),
            config={"binary": "smbclient", "flags": ["-N", "-g"]},
        )

        self.assertTrue(result.ok)
        self.assertTrue(result.warnings)
        self.assertFalse(result.negative_observation)

    @patch("blackline.tools.network.smbclient.resolve_external_binary", return_value=("", "smbclient is unavailable"))
    def test_missing_binary_is_a_graceful_skip(self, _resolver):
        result = enumerate_smb_shares("10.0.0.5", config={"binary": "smbclient"})

        self.assertTrue(result.skipped)
        self.assertFalse(result.ok)

    def test_command_is_an_anonymous_grepable_listing(self):
        self.assertEqual(
            build_smbclient_command("10.0.0.5", port=445, config={"binary": "smbclient", "flags": ["-N", "-g"]}),
            ("smbclient", "-L", "//10.0.0.5", "-p", "445", "-N", "-g"),
        )


if __name__ == "__main__":
    unittest.main()
