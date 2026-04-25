import io
import unittest
from contextlib import redirect_stdout

from blackline.cli.commands.tools import recon_cmd
from blackline.cli.core_shell import dispatch_line, is_recon_command
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.engine.executor import StepResult
from blackline.engine.planner import ExecutionPlan, PlanStep
from blackline.engine.runner import RunResult
from blackline.engine.state.context import ExecutionContext


class ReconCommandTests(unittest.TestCase):
    def test_handle_recon_renders_result_summary(self):
        original_run_expression = recon_cmd.run_expression

        recon_cmd.run_expression = lambda expression, session: RunResult(
            context=ExecutionContext(expression=expression, module="recon", params={"target": "192.168.1.1"}),
            plan=ExecutionPlan(
                context=ExecutionContext(expression=expression, module="recon", params={"target": "192.168.1.1"}),
                steps=(PlanStep(tool="nmap", action="scan", params={"target": "192.168.1.1"}),),
            ),
            results=(
                StepResult(
                    tool="nmap",
                    action="scan",
                    ok=True,
                    payload={
                        "command": ["nmap", "-Pn", "-T3", "-p", "1-1024", "192.168.1.1"],
                        "target": "192.168.1.1",
                        "host_status": "up",
                        "elapsed_seconds": 49.96,
                        "ports": [
                            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                        ],
                        "warnings": [],
                    },
                ),
            ),
        )

        output = io.StringIO()
        try:
            with redirect_stdout(output):
                ok = recon_cmd.handle_recon("recon[target=192.168.1.1]", active_job="A12F", use_color=False)
        finally:
            recon_cmd.run_expression = original_run_expression

        self.assertTrue(ok)
        text = output.getvalue()
        self.assertIn("nmap -Pn -T3 -p 1-1024 192.168.1.1", text)
        self.assertIn("PORT    STATE SERVICE", text)
        self.assertIn("22/tcp  open  ssh", text)
        self.assertIn("80/tcp  open  http", text)
        self.assertIn("[result] 2 open ports (50.0s) -> #A12F", text)

    def test_handle_recon_counts_only_open_ports_in_summary(self):
        original_run_expression = recon_cmd.run_expression

        recon_cmd.run_expression = lambda expression, session: RunResult(
            context=ExecutionContext(expression=expression, module="recon", params={"target": "10.0.0.1"}),
            plan=ExecutionPlan(
                context=ExecutionContext(expression=expression, module="recon", params={"target": "10.0.0.1"}),
                steps=(PlanStep(tool="nmap", action="scan", params={"target": "10.0.0.1"}),),
            ),
            results=(
                StepResult(
                    tool="nmap",
                    action="scan",
                    ok=True,
                    payload={
                        "command": ["nmap", "-Pn", "-T3", "-p", "1-1024", "10.0.0.1"],
                        "target": "10.0.0.1",
                        "host_status": "up",
                        "elapsed_seconds": 224.28,
                        "raw_output": (
                            "Starting Nmap 7.99 ( https://nmap.org ) at 2026-04-25 00:33 -0400\n"
                            "Nmap scan report for 10.0.0.1\n"
                            "Host is up (1.0s latency).\n"
                            "PORT    STATE    SERVICE\n"
                            "22/tcp  filtered ssh\n"
                            "23/tcp  filtered telnet\n"
                            "53/tcp  open     domain\n"
                            "80/tcp  open     http\n"
                            "111/tcp filtered rpcbind\n"
                            "443/tcp open     https\n"
                        ),
                        "ports": [
                            {"port": 22, "protocol": "tcp", "state": "filtered", "service": "ssh"},
                            {"port": 23, "protocol": "tcp", "state": "filtered", "service": "telnet"},
                            {"port": 53, "protocol": "tcp", "state": "open", "service": "domain"},
                            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                            {"port": 111, "protocol": "tcp", "state": "filtered", "service": "rpcbind"},
                            {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
                        ],
                        "warnings": [],
                    },
                ),
            ),
        )

        output = io.StringIO()
        try:
            with redirect_stdout(output):
                ok = recon_cmd.handle_recon("recon[target=10.0.0.1]", active_job="NFID", use_color=False)
        finally:
            recon_cmd.run_expression = original_run_expression

        self.assertTrue(ok)
        self.assertIn("[result] 3 open ports (3m 44.3s) -> #NFID", output.getvalue())

    def test_dispatch_line_routes_recon_expression(self):
        output = io.StringIO()
        original_handle_recon = recon_cmd.handle_recon
        original_core_handle_recon = dispatch_line.__globals__["handle_recon"]
        original_handle_new = dispatch_line.__globals__["handle_new"]
        called = {"expression": ""}
        created = {"expression": "", "render_summary": None}

        def fake_handle_recon(expression: str, *, active_job: str = "", use_color: bool | None = None) -> bool:
            called["expression"] = expression
            called["active_job"] = active_job
            print("[result] fake recon")
            return True

        def fake_handle_new(
            expression: str,
            state: ShellState,
            *,
            jobs_root=None,
            created_at=None,
            job_id=None,
            render_summary: bool = True,
            announce_entry: bool = True,
            use_color: bool | None = None,
        ) -> bool:
            created["expression"] = expression
            created["render_summary"] = render_summary
            state.active_job = "A12F"
            return True

        recon_cmd.handle_recon = fake_handle_recon
        dispatch_line.__globals__["handle_recon"] = fake_handle_recon
        dispatch_line.__globals__["handle_new"] = fake_handle_new
        try:
            with redirect_stdout(output):
                should_exit = dispatch_line("recon[target=10.0.0.1]", ShellState())
        finally:
            recon_cmd.handle_recon = original_handle_recon
            dispatch_line.__globals__["handle_recon"] = original_core_handle_recon
            dispatch_line.__globals__["handle_new"] = original_handle_new

        self.assertFalse(should_exit)
        self.assertEqual(created["expression"], "recon[target=10.0.0.1]")
        self.assertFalse(created["render_summary"])
        self.assertEqual(called["expression"], "recon[target=10.0.0.1]")
        self.assertEqual(called["active_job"], "A12F")
        self.assertEqual(output.getvalue().strip(), "[result] fake recon")

    def test_dispatch_line_routes_spaced_recon_expression(self):
        output = io.StringIO()
        original_handle_recon = recon_cmd.handle_recon
        original_core_handle_recon = dispatch_line.__globals__["handle_recon"]
        original_handle_new = dispatch_line.__globals__["handle_new"]
        called = {"expression": ""}
        created = {"expression": "", "render_summary": None}

        def fake_handle_recon(expression: str, *, active_job: str = "", use_color: bool | None = None) -> bool:
            called["expression"] = expression
            called["active_job"] = active_job
            print("[result] fake recon")
            return True

        def fake_handle_new(
            expression: str,
            state: ShellState,
            *,
            jobs_root=None,
            created_at=None,
            job_id=None,
            render_summary: bool = True,
            announce_entry: bool = True,
            use_color: bool | None = None,
        ) -> bool:
            created["expression"] = expression
            created["render_summary"] = render_summary
            state.active_job = "B93K"
            return True

        recon_cmd.handle_recon = fake_handle_recon
        dispatch_line.__globals__["handle_recon"] = fake_handle_recon
        dispatch_line.__globals__["handle_new"] = fake_handle_new
        try:
            with redirect_stdout(output):
                should_exit = dispatch_line(
                    "recon [target= 10.0.0.1, strategy=balanced, speed=normal,  probe=surface]",
                    ShellState(),
                )
        finally:
            recon_cmd.handle_recon = original_handle_recon
            dispatch_line.__globals__["handle_recon"] = original_core_handle_recon
            dispatch_line.__globals__["handle_new"] = original_handle_new

        self.assertFalse(should_exit)
        self.assertTrue(is_recon_command("recon [target=10.0.0.1]"))
        self.assertEqual(
            created["expression"],
            "recon [target= 10.0.0.1, strategy=balanced, speed=normal,  probe=surface]",
        )
        self.assertFalse(created["render_summary"])
        self.assertEqual(
            called["expression"],
            "recon [target= 10.0.0.1, strategy=balanced, speed=normal,  probe=surface]",
        )
        self.assertEqual(called["active_job"], "B93K")
        self.assertEqual(output.getvalue().strip(), "[result] fake recon")

    def test_dispatch_line_reuses_existing_job_for_recon(self):
        output = io.StringIO()
        original_handle_recon = recon_cmd.handle_recon
        original_core_handle_recon = dispatch_line.__globals__["handle_recon"]
        original_handle_new = dispatch_line.__globals__["handle_new"]
        called = {"expression": ""}
        created = {"count": 0}

        def fake_handle_recon(expression: str, *, active_job: str = "", use_color: bool | None = None) -> bool:
            called["expression"] = expression
            called["active_job"] = active_job
            print("[result] fake recon")
            return True

        def fake_handle_new(*args, **kwargs) -> bool:
            created["count"] += 1
            return True

        recon_cmd.handle_recon = fake_handle_recon
        dispatch_line.__globals__["handle_recon"] = fake_handle_recon
        dispatch_line.__globals__["handle_new"] = fake_handle_new
        try:
            with redirect_stdout(output):
                should_exit = dispatch_line("recon[target=10.0.0.1]", ShellState(active_job="Z9Q2"))
        finally:
            recon_cmd.handle_recon = original_handle_recon
            dispatch_line.__globals__["handle_recon"] = original_core_handle_recon
            dispatch_line.__globals__["handle_new"] = original_handle_new

        self.assertFalse(should_exit)
        self.assertEqual(created["count"], 0)
        self.assertEqual(called["active_job"], "Z9Q2")
        self.assertEqual(output.getvalue().strip(), "[result] fake recon")

    def test_dispatch_line_does_not_auto_create_job_for_invalid_recon(self):
        output = io.StringIO()
        original_handle_recon = recon_cmd.handle_recon
        original_core_handle_recon = dispatch_line.__globals__["handle_recon"]
        original_handle_new = dispatch_line.__globals__["handle_new"]
        created = {"count": 0}

        def fake_handle_recon(expression: str, *, active_job: str = "", use_color: bool | None = None) -> bool:
            print("[error] unknown recon argument: targe (did you mean target?)")
            return False

        def fake_handle_new(*args, **kwargs) -> bool:
            created["count"] += 1
            return True

        recon_cmd.handle_recon = fake_handle_recon
        dispatch_line.__globals__["handle_recon"] = fake_handle_recon
        dispatch_line.__globals__["handle_new"] = fake_handle_new
        try:
            with redirect_stdout(output):
                should_exit = dispatch_line("recon [targe=10.0.0.1]", ShellState())
        finally:
            recon_cmd.handle_recon = original_handle_recon
            dispatch_line.__globals__["handle_recon"] = original_core_handle_recon
            dispatch_line.__globals__["handle_new"] = original_handle_new

        self.assertFalse(should_exit)
        self.assertEqual(created["count"], 0)
        self.assertEqual(
            output.getvalue().strip(),
            "[error] unknown recon argument: targe (did you mean target?)",
        )

    def test_handle_recon_rejects_unknown_argument(self):
        output = io.StringIO()

        with redirect_stdout(output):
            ok = recon_cmd.handle_recon(
                "recon [targe= 10.0.0.1, strategy=balanced, speed=normal, probe=surface]",
                use_color=False,
            )

        self.assertFalse(ok)
        self.assertEqual(
            output.getvalue().strip(),
            "[error] unknown recon argument: targe (did you mean target?)",
        )

    def test_handle_recon_requires_target(self):
        output = io.StringIO()

        with redirect_stdout(output):
            ok = recon_cmd.handle_recon(
                "recon [strategy=balanced, speed=normal, probe=surface]",
                use_color=False,
            )

        self.assertFalse(ok)
        self.assertEqual(output.getvalue().strip(), "[error] missing required recon argument: target")


if __name__ == "__main__":
    unittest.main()
