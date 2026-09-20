"""Contracts for verified external-tool discovery."""

from __future__ import annotations

import unittest

from blackline.pathfinder import Pathfinder
from blackline.utils.exec import CommandResult


class PathfinderTests(unittest.TestCase):
    def test_skips_python_httpx_and_resolves_projectdiscovery_httpx(self):
        results = {
            "/python/httpx": CommandResult(("/python/httpx", "-version"), 2, "", "Usage: httpx [OPTIONS] URL", 0.01),
            "/projectdiscovery/httpx": CommandResult(
                ("/projectdiscovery/httpx", "-version"),
                0,
                "ProjectDiscovery\n[INF] Current Version: v1.12.0",
                "",
                0.01,
            ),
        }
        pathfinder = Pathfinder(
            executable_resolver=lambda _: "/python/httpx",
            path_entries=lambda: ["/python", "/projectdiscovery"],
            candidate_finder=lambda _: ("/python/httpx", "/projectdiscovery/httpx"),
            command_runner=lambda command, _: results[command[0]],
        )
        resolved = pathfinder.require("httpx")

        self.assertTrue(resolved.valid)
        self.assertEqual(resolved.path, "/projectdiscovery/httpx")
        self.assertIn("v1.12.0", resolved.version)

    def test_rejects_a_same_named_binary_without_the_required_fingerprint(self):
        pathfinder = Pathfinder(
            candidate_finder=lambda _: ("/python/httpx",),
            command_runner=lambda command, _: CommandResult(command, 0, "[INF] Current Version: v1.12.0", "", 0.01),
        )

        resolved = pathfinder.require("httpx")

        self.assertFalse(resolved.valid)
        self.assertIn("expected ProjectDiscovery", resolved.detail)


if __name__ == "__main__":
    unittest.main()
