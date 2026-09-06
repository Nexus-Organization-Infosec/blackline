"""End-to-end contracts for Vector-driven iterative reconnaissance."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from blackline.engine.executor import StepResult
from blackline.engine.runner import parse_expression, run_expression
from blackline.core.recon.vector_adapter import create_recon_vector, execute_followup_plan, observations_from_results


class VectorReconTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = parse_expression("recon[target=10.0.0.174,strategy=auto]")
        self.discovery = StepResult(
            tool="nmap",
            action="port_scan",
            ok=True,
            payload={
                "provider": "nmap",
                "target": "10.0.0.174",
                "ports": [
                    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                    {"port": 111, "protocol": "tcp", "state": "open", "service": "rpcbind"},
                    {"port": 3000, "protocol": "tcp", "state": "open", "service": "http"},
                ],
            },
        )

    def test_pi_juice_shop_discovery_creates_web_followups_after_round_one(self):
        vector = create_recon_vector(self.context)
        observations = observations_from_results((self.discovery,), fallback_host="10.0.0.174")
        decision = vector.observe(observations)

        self.assertEqual(
            [(candidate.intent.verb, candidate.intent.subject, candidate.target) for candidate in decision.selected],
            [("probe", "http", "10.0.0.174:3000"), ("fingerprint", "http", "10.0.0.174:3000")],
        )
        self.assertTrue(vector.state.tags)
        self.assertTrue(all(tag.origin == "derived" for tag in vector.state.tags))
        self.assertTrue(all(tag.source_evidence for tag in vector.state.tags))

        followup = execute_followup_plan(self.context, decision)
        self.assertEqual([step.tool for step in followup.steps], ["http", "fingerprint"])
        self.assertEqual([step.params["port"] for step in followup.steps], ["3000", "3000"])

    def test_completed_actions_are_not_reintroduced_by_later_evidence(self):
        vector = create_recon_vector(self.context)
        first = vector.observe(observations_from_results((self.discovery,), fallback_host="10.0.0.174"))
        for candidate in first.selected:
            vector.mark_completed(candidate)
        web_result = StepResult(
            tool="http",
            action="http_ip_probe",
            ok=True,
            payload={"provider": "urllib", "findings": [{"url": "http://10.0.0.174:3000", "ok": True}]},
        )

        later = vector.observe(observations_from_results((web_result,), fallback_host="10.0.0.174"))
        self.assertEqual(later.selected, ())

    def test_strategy_and_explicit_transport_constrain_followups(self):
        surface = create_recon_vector(parse_expression("recon[target=10.0.0.174,strategy=surface]"))
        surface_decision = surface.observe(observations_from_results((self.discovery,), fallback_host="10.0.0.174"))
        self.assertEqual(len(surface_decision.selected), 1)

        udp = create_recon_vector(parse_expression("recon[target=10.0.0.174,strategy=deep,transport=udp]"))
        udp_decision = udp.observe(observations_from_results((self.discovery,), fallback_host="10.0.0.174"))
        self.assertEqual(udp_decision.selected, ())

    def test_empty_or_failed_nmap_discovery_uses_configured_non_nmap_fallback(self):
        vector = create_recon_vector(self.context)
        empty_scan = StepResult(
            tool="nmap",
            action="port_scan",
            ok=True,
            payload={"provider": "nmap", "target": "10.0.0.174", "ports": [], "negative_observation": True},
        )
        decision = vector.observe(observations_from_results((empty_scan,), fallback_host="10.0.0.174"))

        self.assertEqual(
            [(candidate.intent.verb, candidate.intent.subject) for candidate in decision.selected],
            [("collect", "network_intelligence_after_empty_scan")],
        )
        followup = execute_followup_plan(self.context, decision)
        self.assertEqual([(step.tool, step.action) for step in followup.steps], [("ipintel", "network_intelligence")])

    def test_runner_re_evaluates_real_round_results_before_stopping(self):
        calls = []

        def fake_execute(plan, **_kwargs):
            calls.append([step.tool for step in plan.steps])
            if calls[-1] == ["nmap"]:
                return (self.discovery,)
            return tuple(
                StepResult(tool=step.tool, action=step.action, ok=True, payload={"provider": step.tool, "findings": []})
                for step in plan.steps
            )

        rounds = []
        with patch("blackline.engine.runner.execute_plan", side_effect=fake_execute):
            run = run_expression(
                "recon[target=10.0.0.174,strategy=auto]",
                vector_callback=rounds.append,
            )

        self.assertEqual(calls, [["nmap"], ["http", "fingerprint"]])
        self.assertEqual([round_.number for round_ in rounds], [1, 2])
        self.assertEqual(len(run.rounds), 2)
        self.assertEqual([result.tool for result in run.results], ["nmap", "http", "fingerprint"])

    def test_non_auto_strategy_keeps_the_original_single_pass_runner(self):
        plans = []
        with patch("blackline.engine.runner.execute_plan", side_effect=lambda plan, **_kwargs: plans.append(plan) or ()):
            run = run_expression("recon[target=10.0.0.174,strategy=balanced]")

        self.assertEqual(len(plans), 1)
        self.assertEqual([step.tool for step in plans[0].steps], ["ipintel", "http", "fingerprint", "tls", "rdap", "nmap"])
        self.assertEqual(run.rounds, ())
