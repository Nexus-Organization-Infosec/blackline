"""Contract tests for Vector's initial adaptive planning cycle."""

from __future__ import annotations

import unittest

from blackline.clt import compile_source
from blackline.clt.ir import ConditionIntent
from blackline.vector import Capability, Goal, Observation, Policy, Vector


class VectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.vector = Vector(Goal("recon", "127.0.0.1", "balanced"))
        self.ssh = Capability.for_action(
            "inspect",
            "ssh",
            requires=(ConditionIntent("service", "ssh", "open"),),
        )
        self.vector.register_capability(self.ssh)

    def test_service_observation_creates_the_correct_next_action(self):
        decision = self.vector.observe(
            [Observation.service(host="127.0.0.1", port=22, protocol="ssh", state="open", source="nmap", confidence=0.98)]
        )

        self.assertEqual(len(decision.selected), 1)
        candidate = decision.selected[0]
        self.assertEqual((candidate.intent.verb, candidate.intent.subject), ("inspect", "ssh"))
        self.assertEqual(candidate.target, "127.0.0.1:22")
        self.assertIn("requirement satisfied: service ssh open", candidate.reason)
        self.assertEqual(candidate.sources, ("nmap",))

    def test_non_matching_capabilities_are_not_candidates(self):
        self.vector.register_capability(
            Capability.for_action("inspect", "tls", requires=(ConditionIntent("service", "https", "open"),))
        )
        decision = self.vector.observe([Observation.service(host="127.0.0.1", port=22, protocol="ssh", state="open", source="nmap")])

        self.assertEqual([candidate.intent.subject for candidate in decision.candidates], ["ssh"])

    def test_equivalent_completed_work_is_not_proposed_again(self):
        first = self.vector.observe([Observation.service(host="127.0.0.1", port=22, protocol="ssh", state="open", source="nmap")])
        self.vector.mark_completed(first.selected[0])
        later = self.vector.decide()

        self.assertEqual(later.candidates, ())
        self.assertEqual(later.selected, ())

    def test_policy_can_block_a_useful_capability(self):
        blocked = Vector(Goal("recon", "127.0.0.1"), policy=Policy(maximum_risk=0))
        blocked.register_capability(
            Capability.for_action("inspect", "ssh", requires=(ConditionIntent("service", "ssh", "open"),), risk=1)
        )
        decision = blocked.observe([Observation.service(host="127.0.0.1", port=22, protocol="ssh", state="open", source="nmap")])

        self.assertEqual(decision.selected, ())
        self.assertIn("exceeds policy limit", decision.rejected[0].reason)

    def test_clt_rule_is_consumed_as_ir_not_source_text(self):
        workflow = compile_source("if port 22 open\n    -> inspect ssh\n")
        vector = Vector(Goal("recon", "127.0.0.1"))
        vector.register_capability(Capability.for_action("inspect", "ssh"))
        vector.register_rule(workflow.statements[0])

        decision = vector.observe([Observation.service(host="127.0.0.1", port=22, protocol="unknown", state="open", source="nmap")])

        self.assertEqual(decision.selected[0].intent.subject, "ssh")
        self.assertIn("CLT rule matched: port 22 open", decision.selected[0].reason)

    def test_state_merges_observation_provenance_without_duplicate_candidates(self):
        self.vector.observe([Observation.service(host="127.0.0.1", port=22, protocol="ssh", state="open", source="nmap")])
        decision = self.vector.observe([Observation.service(host="127.0.0.1", port=22, protocol="ssh", state="open", source="banner")])

        self.assertEqual(len(self.vector.state.services), 1)
        self.assertEqual(self.vector.state.services[0].sources, ("banner", "nmap"))
        self.assertEqual(len(decision.selected), 1)
        self.assertEqual(decision.selected[0].sources, ("banner", "nmap"))

    def test_generic_structured_facts_can_enable_a_capability(self):
        self.vector.register_capability(
            Capability.for_action("collect", "evidence", requires=(ConditionIntent("finding", "credential", "found"),))
        )
        decision = self.vector.observe(
            [Observation("finding", {"entity": "finding", "value": "credential", "state": "found"}, "user")]
        )

        self.assertEqual(decision.selected[0].intent.verb, "collect")
        self.assertEqual(decision.selected[0].target, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
