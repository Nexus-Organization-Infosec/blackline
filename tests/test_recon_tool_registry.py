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
from blackline.pathfinder import ToolResolution
from blackline.utils.tab_complete import completion_items


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
        self.assertIn("provider", text)

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

    def test_tools_command_routes_uninstall_subcommand(self):
        with patch("blackline.cli.commands.system.tools_cmd.handle_uninstall", return_value=True) as uninstall:
            self.assertTrue(handle_tools("uninstall httpx", use_color=False))

        uninstall.assert_called_once_with("httpx", use_color=False)

    def test_tools_command_routes_install_subcommand(self):
        with patch("blackline.cli.commands.system.tools_cmd.handle_install", return_value=True) as install:
            self.assertTrue(handle_tools("install httpx", use_color=False))

        install.assert_called_once_with("httpx", use_color=False)

    def test_completion_is_registry_backed(self):
        self.assertIn(("recon", "tool group"), completion_items("tools r"))
        self.assertIn(("naabu", "tool"), completion_items("tools na"))

    @patch("blackline.core.recon.tool_registry.Pathfinder")
    def test_external_health_check_uses_pathfinder_resolution(self, pathfinder):
        pathfinder.return_value.locate.return_value = ToolResolution("naabu", path="/usr/local/bin/naabu", candidates=("/usr/local/bin/naabu",))
        pathfinder.return_value.require.return_value = ToolResolution(
            "naabu", path="/usr/local/bin/naabu", version="v2.3.0", valid=True, candidates=("/usr/local/bin/naabu",)
        )

        check = check_recon_tool(get_recon_tool("naabu"))

        self.assertEqual(check.status, "ready")
        self.assertIn("v2.3.0", check.version)
        self.assertEqual(check.path, "/usr/local/bin/naabu")

    @patch("blackline.core.recon.tool_registry.Pathfinder")
    def test_missing_external_binary_is_reported_without_running_a_probe(self, pathfinder):
        pathfinder.return_value.locate.return_value = ToolResolution("naabu", detail="naabu is unavailable")
        check = check_recon_tool(get_recon_tool("naabu"))

        self.assertEqual(check.status, "unavailable")

    @patch("blackline.core.recon.tool_registry.Pathfinder")
    def test_failed_health_probe_is_unhealthy(self, pathfinder):
        pathfinder.return_value.locate.return_value = ToolResolution("naabu", path="/usr/local/bin/naabu", candidates=("/usr/local/bin/naabu",))
        pathfinder.return_value.require.return_value = ToolResolution(
            "naabu", path="/usr/local/bin/naabu", version="unknown", detail="identity check exited 1", candidates=("/usr/local/bin/naabu",)
        )

        check = check_recon_tool(get_recon_tool("naabu"))

        self.assertEqual(check.status, "unhealthy")
        self.assertIn("exited 1", check.detail)


if __name__ == "__main__":
    unittest.main()
