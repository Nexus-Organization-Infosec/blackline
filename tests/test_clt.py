"""Fixture-free contract tests for the CLT v0 compiler and runtime."""

from __future__ import annotations

import unittest

from blackline.clt import CLTRuntime, CapabilityRegistry, LexError, NormalizationError, ParseError, ValidationError, compile_source, default_vocabulary
from blackline.clt.ir import IRRule
from blackline.clt.vocabulary import WordClass


class CLTCompilerTests(unittest.TestCase):
    def test_equivalent_condition_orders_compile_to_identical_ir(self):
        first = compile_source("if port 22 open\n    -> inspect ssh\n")
        second = compile_source("if open 22 port\n    -> inspect ssh\n")
        self.assertEqual(first, second)
        rule = first.statements[0]
        self.assertIsInstance(rule, IRRule)
        self.assertEqual((rule.condition.entity, rule.condition.value, rule.condition.state), ("port", "22", "open"))

    def test_representative_recon_workflow_compiles(self):
        workflow = compile_source(
            "target = 127.0.0.1\n\n"
            "recon[target, strategy=deep]\n"
            "    -> analyze\n\n"
            "    if service http found\n"
            "        -> inspect web\n"
        )
        operation = workflow.statements[1]
        self.assertEqual(operation.intent.verb, "recon")
        self.assertEqual(operation.inputs, ("target",))
        self.assertEqual(operation.options, (("strategy", "deep"),))

    def test_action_word_order_is_normalized_when_unambiguous(self):
        standard = compile_source("-> inspect ssh\n")
        reordered = compile_source("-> ssh inspect\n")
        self.assertEqual(standard, reordered)

    def test_unknown_action_has_a_source_friendly_suggestion(self):
        with self.assertRaises(ValidationError) as raised:
            compile_source("analyse[target]\n", filename="audit.clt")
        self.assertIn("unknown word 'analyse'", str(raised.exception))
        self.assertIn("did you mean 'analyze'?", str(raised.exception))
        self.assertIn("audit.clt:1:1", str(raised.exception))

    def test_incomplete_port_condition_is_not_guessed(self):
        with self.assertRaises(NormalizationError) as raised:
            compile_source("if port open\n    -> inspect ssh\n")
        self.assertIn("port number is required", str(raised.exception))

    def test_indentation_is_validated(self):
        with self.assertRaises(LexError):
            compile_source("if port 22 open\n  -> inspect ssh\n")
        with self.assertRaises(ParseError):
            compile_source("if port 22 open\n")

    def test_plugin_vocabulary_can_extend_domain_terms(self):
        vocabulary = default_vocabulary()
        vocabulary.register("redis", WordClass.DOMAIN)
        workflow = compile_source("if service redis found\n    -> inspect redis\n", vocabulary=vocabulary)
        self.assertEqual(workflow.statements[0].condition.value, "redis")

    def test_else_is_parsed_as_the_other_condition_branch(self):
        workflow = compile_source(
            "if port 22 open\n"
            "    -> inspect ssh\n"
            "else\n"
            "    -> report\n"
        )
        rule = workflow.statements[0]
        self.assertEqual(rule.else_body[0].intent.verb, "report")


class CLTRuntimeTests(unittest.TestCase):
    def test_runtime_resolves_registered_capabilities_and_facts(self):
        events: list[str] = []
        registry = CapabilityRegistry()
        registry.register("recon", handler=lambda invocation: {"target": invocation.inputs[0]})
        registry.register("analyze", handler=lambda invocation: events.append("analyze") or {})
        registry.register("inspect", "ssh", handler=lambda invocation: events.append("ssh") or {"inspected": "ssh"})
        runtime = CLTRuntime(registry)
        workflow = compile_source(
            "target = 127.0.0.1\n"
            "recon[target]\n"
            "    -> analyze\n"
            "    if open port 22\n"
            "        -> inspect ssh\n"
        )
        result = runtime.run(workflow, facts={("port", "22"): "open"})
        self.assertEqual(result.variables["target"], "127.0.0.1")
        self.assertEqual(events, ["analyze", "ssh"])
        self.assertEqual([event.intent.verb for event in result.events], ["recon", "analyze", "inspect"])

    def test_runtime_follows_else_when_a_condition_is_not_observed(self):
        registry = CapabilityRegistry()
        registry.register("inspect", "ssh")
        registry.register("report")
        result = CLTRuntime(registry).run(
            compile_source("if port 22 open\n    -> inspect ssh\nelse\n    -> report\n"),
            facts={("port", "22"): "closed"},
        )
        self.assertEqual([event.intent.verb for event in result.events], ["report"])


if __name__ == "__main__":
    unittest.main()
