"""Strategy-to-Nmap policy contract tests."""

from __future__ import annotations

import unittest

from blackline.core.recon.scan_policy import nmap_policy_params
from blackline.engine.context import ExecutionContext
from blackline.engine.planner import build_plan
from blackline.tools.network.nmap import NmapRequest, build_nmap_command


class NmapScanPolicyTests(unittest.TestCase):
    def test_strategy_baselines_materialize_the_documented_nmap_commands(self):
        expected = {
            "surface": ("nmap", "-Pn", "--top-ports", "100", "10.0.0.1"),
            "fast": ("nmap", "-Pn", "-T4", "--top-ports", "1000", "10.0.0.1"),
            "balanced": ("nmap", "-Pn", "-T3", "--top-ports", "5000", "-sV", "10.0.0.1"),
            "quiet": ("nmap", "-Pn", "-T2", "--top-ports", "1000", "-sV", "10.0.0.1"),
            "deep": ("nmap", "-Pn", "-T4", "-p-", "-sV", "-O", "10.0.0.1"),
            "udp": ("nmap", "-Pn", "-sU", "--top-ports", "100", "10.0.0.1"),
        }
        for strategy, command in expected.items():
            with self.subTest(strategy=strategy):
                params = nmap_policy_params({"strategy": strategy})
                request = NmapRequest(
                    target="10.0.0.1",
                    ports=params["ports"],
                    top_ports=params["top_ports"],
                    profile=params["profile"],
                    timing=params["timing"],
                    service_detection=params["service_detection"] == "true",
                    os_detection=params["os_detection"] == "true",
                    use_default_timing=params["use_default_timing"] == "true",
                )
                self.assertEqual(build_nmap_command(request), command)

    def test_custom_settings_override_policy_without_changing_other_baselines(self):
        params = nmap_policy_params({"strategy": "deep", "ports": "22,443", "speed": "low", "probe": "service"})

        self.assertEqual(params["ports"], "22,443")
        self.assertEqual(params["top_ports"], "")
        self.assertEqual(params["timing"], "T2")
        self.assertEqual(params["service_detection"], "true")
        self.assertEqual(params["os_detection"], "false")

    def test_planner_materializes_balanced_policy_for_a_normal_recon(self):
        plan = build_plan(ExecutionContext("recon[target=example.com]", "recon", {"target": "example.com"}))
        nmap = next(step for step in plan.steps if step.tool == "nmap")

        self.assertEqual(nmap.params["profile"], "balanced")
        self.assertEqual(nmap.params["top_ports"], "5000")
        self.assertEqual(nmap.params["service_detection"], "true")
