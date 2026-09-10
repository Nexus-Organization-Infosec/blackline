"""Contracts for the optional ProjectDiscovery Naabu adapter."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from blackline.tools.network.naabu import build_naabu_command, scan_ports_with_naabu
from blackline.tools.parsers.naabu import parse_naabu_jsonl
from blackline.engine.context import ExecutionContext
from blackline.engine.executor import execute_plan
from blackline.engine.planner import ExecutionPlan, PlanStep
from blackline.utils.exec import CommandResult


class NaabuToolTests(unittest.TestCase):
    def test_parser_preserves_unique_open_ports(self):
        findings = parse_naabu_jsonl(
            '\n'.join((
                '{"host":"example.com","ip":"93.184.216.34","port":443}',
                '{"host":"example.com","port":80}',
                '{"host":"example.com","port":443}',
                'not json',
            ))
        )

        self.assertEqual(findings, [
            {"host": "example.com", "port": 80, "protocol": "tcp"},
            {"host": "example.com", "port": 443, "protocol": "tcp"},
        ])

    def test_adapter_returns_open_port_evidence(self):
        result = scan_ports_with_naabu(
            "example.com",
            top_ports="1000",
            executor=lambda command: CommandResult(command, 0, '{"host":"example.com","port":443}\n', "", 0.1),
            config={"binary": "naabu", "flags": ["-json", "-silent"]},
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.ports[0].port, 443)
        self.assertFalse(result.negative_observation)

    def test_broader_nmap_top_port_policy_keeps_coverage(self):
        command = build_naabu_command("example.com", top_ports="5000", config={"flags": ["-json"]})

        self.assertEqual(command, ("naabu", "-host", "example.com", "-p", "-", "-json"))

    def test_nmap_enriches_only_naabu_discovered_ports(self):
        plan = ExecutionPlan(
            ExecutionContext(expression="recon[target=example.com]", module="recon"),
            steps=(
                PlanStep("naabu", "fast_port_discovery", {"target": "example.com", "top_ports": "1000"}),
                PlanStep("nmap", "port_scan", {"target": "example.com", "profile": "balanced", "service_detection": "true", "use_default_timing": "true"}, execution_group=1),
            ),
        )
        commands: list[tuple[str, ...]] = []

        def executor(command: tuple[str, ...]) -> CommandResult:
            commands.append(command)
            if command[0] == "naabu":
                return CommandResult(command, 0, '{"host":"example.com","port":22}\n{"host":"example.com","port":443}\n', "", 0.1)
            return CommandResult(command, 0, "Nmap scan report for example.com\n22/tcp open ssh\n443/tcp open https\n", "", 0.1)

        results = execute_plan(plan, command_executor=executor)

        self.assertEqual([result.tool for result in results], ["naabu", "nmap"])
        self.assertIn("-p", commands[1])
        self.assertEqual(commands[1][commands[1].index("-p") + 1], "22,443")

    def test_successful_empty_naabu_result_skips_nmap(self):
        plan = ExecutionPlan(
            ExecutionContext(expression="recon[target=example.com]", module="recon"),
            steps=(
                PlanStep("naabu", "fast_port_discovery", {"target": "example.com", "top_ports": "1000"}),
                PlanStep("nmap", "port_scan", {"target": "example.com", "profile": "balanced"}, execution_group=1),
            ),
        )
        commands: list[tuple[str, ...]] = []

        results = execute_plan(plan, command_executor=lambda command: (commands.append(command) or CommandResult(command, 0, "", "", 0.1)))

        self.assertEqual([result.outcome for result in results], ["negative", "skipped"])
        self.assertEqual(len(commands), 1)

    @patch("blackline.tools.network.naabu.which", return_value=None)
    def test_missing_binary_is_a_graceful_skip(self, _which):
        result = scan_ports_with_naabu("example.com", config={"binary": "naabu"})

        self.assertTrue(result.skipped)
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
