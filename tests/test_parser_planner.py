import unittest

from frontend.parser.intent_parser import parse_intent
from midend.planner import plan_intent


class ParserPlannerTests(unittest.TestCase):
    def test_recon_intent_plans_default_task(self):
        intent = parse_intent("recon [ip=127.0.0.1]")
        tasks = plan_intent(intent)

        self.assertEqual(intent["errors"], [])
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["action"], "recon")
        self.assertEqual(tasks[0]["target"], {"type": "ip", "value": "127.0.0.1"})
        self.assertEqual(tasks[0]["intent"]["ports"], "top1000")

    def test_operator_symbol_maps_to_configured_name(self):
        intent = parse_intent("recon [ip=127.0.0.1] &")
        tasks = plan_intent(intent)

        self.assertEqual(intent["operators"], [{"symbol": "&", "name": "background"}])
        self.assertTrue(tasks[0]["execution"]["background"])

    def test_longest_operator_symbol_wins(self):
        intent = parse_intent("recon [ip=1.1.1.1] && recon [ip=2.2.2.2]")

        self.assertEqual(intent["operators"], [{"symbol": "&&", "name": "and-sequence"}])


if __name__ == "__main__":
    unittest.main()
