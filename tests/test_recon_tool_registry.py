"""Contracts for recon's metadata-backed provider registry."""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from blackline.cli.commands.system.tools_cmd import handle_tools
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.cli.dispatcher import dispatch_command
from blackline.core.recon.pipeline import build_recon_pipeline
from blackline.core.recon.tool_registry import get_recon_tool, providers_for, set_recon_tool_enabled
from blackline.core.recon.tool_registry import check_recon_tool
from blackline.utils.tab_complete import completion_items
from blackline.utils.exec import CommandResult


class ReconToolRegistryTests(unittest.TestCase):
    def test_registry_exposes_provider_capability_contracts(self):
        naabu = get_recon_tool("naabu")

        self.assertIsNotNone(naabu)
        self.assertEqual(naabu.capability, "port-discovery")
        self.assertEqual(naabu.produces, ("host.port",))
        self.assertEqual([tool.name for tool in providers_for("host.port")], ["naabu", "nmap"])
        smbclient = get_recon_tool("smbclient")
        self.assertIsNotNone(smbclient)
        self.assertEqual(smbclient.capability, "smb-share-enumeration")
        self.assertEqual(smbclient.produces, ("smb.share",))

    def test_top_level_tools_listing_and_inspection_are_registry_backed(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertTrue(handle_tools("recon", use_color=False))
            self.assertTrue(handle_tools("naabu", use_color=False))

        text = output.getvalue()
        self.assertIn("RECON TOOLS", text)
        self.assertIn("naabu", text)
        self.assertIn("port-discovery", text)
        self.assertIn("NAABU", text)
        self.assertIn("produces", text)
        self.assertIn("installed", text)

    def test_tool_list_omits_install_locations_until_a_specific_tool_is_requested(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertTrue(handle_tools("recon", use_color=False))

        self.assertNotIn("LOCATION", output.getvalue())
        self.assertNotIn("installed", output.getvalue().lower())

    def test_disable_changes_future_pipeline_selection(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"BLACKLINE_DATA_DIR": directory}):
            self.assertTrue(set_recon_tool_enabled("naabu", False))
            self.assertNotIn("naabu", [step.tool for step in build_recon_pipeline("10.0.0.1").steps])
            self.assertTrue(set_recon_tool_enabled("naabu", True))
            self.assertIn("naabu", [step.tool for step in build_recon_pipeline("10.0.0.1").steps])

    def test_dispatcher_routes_top_level_tools_without_starting_a_job(self):
        with patch("blackline.cli.dispatcher.handle_tools", return_value=True) as handler:
            response = dispatch_command("tools naabu", ShellState())

        self.assertEqual(response.exit_code, 0)
        handler.assert_called_once_with("naabu")

    def test_completion_is_registry_backed(self):
        self.assertIn(("recon", "tool group"), completion_items("tools r"))
        self.assertIn(("naabu", "tool"), completion_items("tools na"))

    @patch("blackline.core.recon.tool_registry.which", return_value="/usr/local/bin/naabu")
    @patch("blackline.core.recon.tool_registry.run_command")
    def test_external_health_check_runs_only_configured_version_probe(self, run_command, _which):
        run_command.return_value = CommandResult(("naabu", "-version"), 0, "[INF] Current Version: v2.3.0\n", "", 0.1)

        check = check_recon_tool(get_recon_tool("naabu"))

        self.assertEqual(check.status, "ready")
        self.assertIn("v2.3.0", check.version)
        run_command.assert_called_once_with(("naabu", "-version"), timeout=3.0)

    @patch("blackline.core.recon.tool_registry.which", return_value=None)
    @patch("blackline.core.recon.tool_registry.run_command")
    def test_missing_external_binary_is_reported_without_running_a_probe(self, run_command, _which):
        check = check_recon_tool(get_recon_tool("naabu"))

        self.assertEqual(check.status, "unavailable")
        run_command.assert_not_called()

    @patch("blackline.core.recon.tool_registry.which", return_value="/usr/local/bin/naabu")
    @patch("blackline.core.recon.tool_registry.run_command")
    def test_failed_health_probe_is_unhealthy(self, run_command, _which):
        run_command.return_value = CommandResult(("naabu", "-version"), 1, "", "bad executable", 0.1)

        check = check_recon_tool(get_recon_tool("naabu"))

        self.assertEqual(check.status, "unhealthy")
        self.assertIn("exited 1", check.detail)


if __name__ == "__main__":
    unittest.main()
