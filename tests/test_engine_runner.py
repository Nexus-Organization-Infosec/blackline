import unittest

from blackline.engine.executor import execute_plan
from blackline.engine.planner import build_plan
from blackline.engine.runner import normalize_expression, parse_expression, run_expression
from blackline.engine.state.context import ExecutionContext
from blackline.engine.state.session import EngineSession
from blackline.utils.exec import CommandResult


class EngineRunnerTests(unittest.TestCase):
    def test_parse_expression_extracts_module_and_params(self):
        context = parse_expression("recon[target=192.168.1.1,ports=80-443]", job_id="A12F")

        self.assertEqual(
            context,
            ExecutionContext(
                expression="recon[target=192.168.1.1,ports=80-443]",
                module="recon",
                params={"target": "192.168.1.1", "ports": "80-443"},
                job_id="A12F",
            ),
        )

    def test_normalize_expression_is_space_insensitive(self):
        expression = "recon [target= 10.0.0.1, strategy=balanced, speed=normal,\n  probe=surface]"

        self.assertEqual(
            normalize_expression(expression),
            "recon[target=10.0.0.1, strategy=balanced, speed=normal, probe=surface]",
        )

    def test_build_plan_for_recon_uses_nmap(self):
        plan = build_plan(
            ExecutionContext(
                expression="recon[target=192.168.1.1]",
                module="recon",
                params={"target": "192.168.1.1"},
            )
        )

        self.assertEqual(len(plan.steps), 1)
        self.assertEqual(plan.steps[0].tool, "nmap")
        self.assertEqual(plan.steps[0].params["target"], "192.168.1.1")
        self.assertEqual(plan.steps[0].params["ports"], "1-1024")

    def test_build_plan_passes_through_scan_variety(self):
        plan = build_plan(
            ExecutionContext(
                expression="recon[target=192.168.1.1,strategy=quiet,top_ports=20,probe=service,speed=high]",
                module="recon",
                params={
                    "target": "192.168.1.1",
                    "strategy": "quiet",
                    "top_ports": "20",
                    "probe": "service",
                    "speed": "high",
                },
            )
        )

        self.assertEqual(plan.steps[0].params["profile"], "stealth")
        self.assertEqual(plan.steps[0].params["top_ports"], "20")
        self.assertEqual(plan.steps[0].params["timing"], "T4")
        self.assertEqual(plan.steps[0].params["service_detection"], "true")

    def test_execute_plan_returns_structured_results(self):
        plan = build_plan(
            ExecutionContext(
                expression="recon[target=192.168.1.1]",
                module="recon",
                params={"target": "192.168.1.1"},
            )
        )

        def fake_executor(args: tuple[str, ...]) -> CommandResult:
            self.assertEqual(args[0], "nmap")
            return CommandResult(
                args=args,
                returncode=0,
                stdout=(
                    "Nmap scan report for 192.168.1.1\n"
                    "Host is up (0.010s latency).\n"
                    "22/tcp open ssh\n"
                    "80/tcp open http\n"
                ),
                stderr="",
                elapsed_seconds=41.2,
            )

        results = execute_plan(plan, command_executor=fake_executor)

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].ok)
        self.assertEqual(results[0].payload["target"], "192.168.1.1")
        self.assertEqual(
            results[0].payload["ports"],
            [
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
            ],
        )
        self.assertEqual(results[0].payload["elapsed_seconds"], 41.2)

    def test_run_expression_tracks_session_runs(self):
        session = EngineSession(active_job="A12F")

        def fake_executor(args: tuple[str, ...]) -> CommandResult:
            return CommandResult(
                args=args,
                returncode=0,
                stdout="Nmap scan report for 192.168.1.1\nHost is up.\n22/tcp open ssh\n",
                stderr="",
                elapsed_seconds=15.5,
            )

        result = run_expression(
            "recon[target=192.168.1.1]",
            session=session,
            command_executor=fake_executor,
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.context.job_id, "A12F")
        self.assertEqual(session.runs, ["recon[target=192.168.1.1]"])


if __name__ == "__main__":
    unittest.main()
