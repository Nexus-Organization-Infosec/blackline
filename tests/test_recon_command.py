import io
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from blackline.cli.commands.recon import recon_cmd
from blackline.cli.commands.system.jobs_cmd import handle_new, load_job
from blackline.cli.core_shell import dispatch_line, is_recon_command
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.engine.executor import ExecutionProgress, StepResult
from blackline.engine.planner import ExecutionPlan, PlanStep
from blackline.engine.runner import RunResult
from blackline.engine.context import ExecutionContext


class ReconCommandTests(unittest.TestCase):
    def test_progress_renderer_uses_stateful_checklist_without_percentages(self):
        class InteractiveOutput(io.StringIO):
            def isatty(self):
                return True

        output = InteractiveOutput()
        plan = ExecutionPlan(
            context=ExecutionContext(expression="recon[target=10.0.0.1]", module="recon"),
            steps=(
                PlanStep(tool="ipintel", action="ipintel"),
                PlanStep(tool="nmap", action="port_scan"),
            ),
        )
        original_stdout = recon_cmd.sys.stdout
        recon_cmd.sys.stdout = output
        try:
            renderer = recon_cmd.ReconProgressRenderer(use_color=True)
            renderer.show_plan(plan)
            renderer.update(ExecutionProgress("started", 0, 2, plan.steps[0]))
            renderer.update(
                ExecutionProgress(
                    "completed",
                    1,
                    2,
                    plan.steps[0],
                    StepResult(tool="ipintel", action="ipintel", ok=True, payload={}),
                )
            )
            renderer.update(ExecutionProgress("started", 1, 2, plan.steps[1]))
            renderer.finish()
        finally:
            recon_cmd.sys.stdout = original_stdout

        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output.getvalue())
        self.assertIn("[plan] preparing 2 checks", text)
        self.assertIn("network intelligence", text)
        self.assertIn("service and system scan", text)
        self.assertIn("running", text)
        self.assertIn("done", text)
        self.assertNotIn("%", text)

    def test_progress_state_treats_closed_http_endpoints_as_done(self):
        state = recon_cmd._progress_state(
            StepResult(
                tool="http",
                action="http_ip_probe",
                ok=False,
                payload={
                    "findings": [
                        {"url": "http://10.0.0.236", "status_code": None, "error": "Connection refused"},
                        {"url": "https://10.0.0.236", "status_code": None, "error": "Connection refused"},
                    ]
                },
                error="Connection refused",
            )
        )

        self.assertEqual(state, "done")

    def test_render_recon_report_uses_curated_findings_and_provenance(self):
        output = io.StringIO()
        payloads = {
            "ipintel": {
                "target": "10.0.0.236",
                "lookup_ip": "10.0.0.236",
                "asn": "AS-PRIVATE",
                "location": "private / internal",
                "latency": 0.6,
                "jitter": 0.1,
                "bandwidth": 25.39,
                "vpn_likely": False,
                "confidence": "low",
                "provider": "yougotmapped",
            },
            "http": {
                "provider": "curl",
                "findings": [
                    {"url": "http://10.0.0.236", "status_code": None},
                    {"url": "https://10.0.0.236", "status_code": None},
                ],
            },
            "nmap": {
                "provider": "nmap",
                "raw_output": "Starting Nmap 7.99",
                "ports": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "ssh",
                        "version": "OpenSSH 10.2",
                    }
                ],
                "system": {
                    "device": "general purpose",
                    "os": "Apple macOS 13.2 (Ventura)",
                    "kernel": "Darwin 22.3.0",
                    "cpe": "cpe:/o:apple:mac_os_x:13.2",
                    "distance": "0 hops",
                },
            },
        }

        with redirect_stdout(output):
            recon_cmd.render_recon_report(payloads, use_color=False)

        text = output.getvalue()
        self.assertIn("network  (source: yougotmapped)", text)
        self.assertIn("web  (source: curl)", text)
        self.assertIn("services  (source: nmap)", text)
        self.assertIn("system  (source: nmap)", text)
        self.assertIn("anonymity  (source: yougotmapped)", text)
        self.assertIn("OpenSSH 10.2", text)
        self.assertIn("Darwin 22.3.0", text)
        self.assertNotIn("Starting Nmap", text)

    def test_handle_recon_renders_result_summary(self):
        original_run_expression = recon_cmd.run_expression

        recon_cmd.run_expression = lambda expression, session, **kwargs: RunResult(
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
                        "open_ports": 2,
                        "filtered_ports": 0,
                        "interesting_ports": 2,
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
        self.assertIn("[info] target 192.168.1.1", text)
        self.assertIn("services  (source: nmap)", text)
        self.assertIn("PORT     STATE    SERVICE    VERSION", text)
        self.assertIn("22/tcp   open", text)
        self.assertIn("ssh", text)
        self.assertIn("80/tcp   open", text)
        self.assertIn("http", text)
        self.assertIn("[result] recon complete -> #A12F", text)

    def test_handle_recon_counts_only_open_ports_in_summary(self):
        original_run_expression = recon_cmd.run_expression

        recon_cmd.run_expression = lambda expression, session, **kwargs: RunResult(
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
                        "open_ports": 3,
                        "filtered_ports": 3,
                        "interesting_ports": 6,
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
        self.assertIn("[result] recon complete -> #NFID", output.getvalue())

    def test_handle_recon_renders_dns_section_for_domain_targets(self):
        original_run_expression = recon_cmd.run_expression

        recon_cmd.run_expression = lambda expression, session, **kwargs: RunResult(
            context=ExecutionContext(expression=expression, module="recon", params={"target": "example.com"}),
            plan=ExecutionPlan(
                context=ExecutionContext(expression=expression, module="recon", params={"target": "example.com"}),
                steps=(
                    PlanStep(tool="dns", action="dns", params={"target": "example.com", "host": "example.com"}),
                    PlanStep(tool="nmap", action="port_scan", params={"target": "example.com"}),
                ),
            ),
            results=(
                StepResult(
                    tool="dns",
                    action="dns",
                    ok=True,
                    payload={
                        "target": "example.com",
                        "host": "example.com",
                        "records": {
                            "A": ["93.184.216.34"],
                            "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
                            "MX": [],
                            "NS": [],
                        },
                        "resolved_ips": ["93.184.216.34"],
                        "provider": "custom",
                        "raw_output": "",
                        "elapsed_seconds": 0.01,
                    },
                ),
                StepResult(
                    tool="nmap",
                    action="port_scan",
                    ok=True,
                    payload={
                        "command": ["nmap", "-Pn", "-T3", "-p", "1-1024", "example.com"],
                        "target": "example.com",
                        "host_status": "up",
                        "elapsed_seconds": 12.4,
                        "open_ports": 2,
                        "filtered_ports": 0,
                        "interesting_ports": 2,
                        "ports": [
                            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
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
                ok = recon_cmd.handle_recon("recon[target=example.com]", active_job="A12F", use_color=False)
        finally:
            recon_cmd.run_expression = original_run_expression

        self.assertTrue(ok)
        text = output.getvalue()
        self.assertIn("dns  (source: custom)", text)
        self.assertIn("a          : 93.184.216.34", text)
        self.assertIn("aaaa       : 2606:2800:220:1:248:1893:25c8:1946", text)
        self.assertNotIn("Starting Nmap", text)
        self.assertIn("[result] recon complete -> #A12F", text)

    def test_handle_recon_renders_ipintel_section(self):
        original_run_expression = recon_cmd.run_expression

        recon_cmd.run_expression = lambda expression, session, **kwargs: RunResult(
            context=ExecutionContext(expression=expression, module="recon", params={"target": "10.0.0.1"}),
            plan=ExecutionPlan(
                context=ExecutionContext(expression=expression, module="recon", params={"target": "10.0.0.1"}),
                steps=(
                    PlanStep(tool="ipintel", action="ipintel", params={"target": "10.0.0.1", "host": "10.0.0.1"}),
                    PlanStep(tool="nmap", action="port_scan", params={"target": "10.0.0.1"}),
                ),
            ),
            results=(
                StepResult(
                    tool="ipintel",
                    action="ipintel",
                    ok=True,
                    payload={
                        "target": "10.0.0.1",
                        "lookup_ip": "10.0.0.1",
                        "asn": "AS-PRIVATE",
                        "org": "Private Network",
                        "location": "private / internal",
                        "latency": 1.0,
                        "vpn_likely": False,
                        "confidence": "low",
                        "jitter": None,
                        "bandwidth": None,
                        "trace": [],
                        "provider": "local",
                        "elapsed_seconds": 0.0,
                    },
                ),
                StepResult(
                    tool="nmap",
                    action="port_scan",
                    ok=True,
                    payload={
                        "command": ["nmap", "-Pn", "-T3", "-p", "1-1024", "10.0.0.1"],
                        "target": "10.0.0.1",
                        "host_status": "up",
                        "elapsed_seconds": 49.96,
                        "open_ports": 1,
                        "filtered_ports": 0,
                        "interesting_ports": 1,
                        "ports": [
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
                ok = recon_cmd.handle_recon("recon[target=10.0.0.1]", active_job="A12F", use_color=False)
        finally:
            recon_cmd.run_expression = original_run_expression

        self.assertTrue(ok)
        text = output.getvalue()
        self.assertIn("network  (source: local)", text)
        self.assertIn("asn        : AS-PRIVATE", text)
        self.assertIn("scope      : private / internal", text)
        self.assertIn("vpn        : unlikely", text)
        self.assertIn("[result] recon complete -> #A12F", text)

    def test_handle_recon_renders_http_section(self):
        original_run_expression = recon_cmd.run_expression

        recon_cmd.run_expression = lambda expression, session, **kwargs: RunResult(
            context=ExecutionContext(expression=expression, module="recon", params={"target": "example.com"}),
            plan=ExecutionPlan(
                context=ExecutionContext(expression=expression, module="recon", params={"target": "example.com"}),
                steps=(
                    PlanStep(tool="http", action="http_probe", params={"target": "example.com", "host": "example.com"}),
                    PlanStep(tool="nmap", action="port_scan", params={"target": "example.com"}),
                ),
            ),
            results=(
                StepResult(
                    tool="http",
                    action="http_probe",
                    ok=True,
                    payload={
                        "target": "example.com",
                        "mode": "http_probe",
                        "provider": "custom",
                        "findings": [
                            {
                                "url": "https://example.com",
                                "status_code": 200,
                                "title": "Example Domain",
                                "redirect_to": "",
                                "headers": {},
                                "ok": True,
                                "error": "",
                            },
                            {
                                "url": "http://example.com",
                                "status_code": 301,
                                "title": "",
                                "redirect_to": "https://example.com",
                                "headers": {},
                                "ok": True,
                                "error": "",
                            },
                        ],
                        "elapsed_seconds": 0.4,
                    },
                ),
                StepResult(
                    tool="nmap",
                    action="port_scan",
                    ok=True,
                    payload={
                        "command": ["nmap", "-Pn", "-T3", "-p", "1-1024", "example.com"],
                        "target": "example.com",
                        "host_status": "up",
                        "elapsed_seconds": 12.4,
                        "open_ports": 1,
                        "filtered_ports": 0,
                        "interesting_ports": 1,
                        "ports": [
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
                ok = recon_cmd.handle_recon("recon[target=example.com]", active_job="A12F", use_color=False)
        finally:
            recon_cmd.run_expression = original_run_expression

        self.assertTrue(ok)
        text = output.getvalue()
        self.assertIn("web  (source: custom)", text)
        self.assertIn("https      : 200  Example Domain", text)
        self.assertIn("http       : 301", text)
        self.assertIn("-> https://example.com", text)
        self.assertIn("[result] recon complete -> #A12F", text)

    def test_handle_recon_marks_mixed_http_and_nmap_success_as_warnings(self):
        original_run_expression = recon_cmd.run_expression

        recon_cmd.run_expression = lambda expression, session, **kwargs: RunResult(
            context=ExecutionContext(expression=expression, module="recon", params={"target": "10.0.0.1"}),
            plan=ExecutionPlan(
                context=ExecutionContext(expression=expression, module="recon", params={"target": "10.0.0.1"}),
                steps=(
                    PlanStep(tool="http", action="http_ip_probe", params={"target": "10.0.0.1", "host": "10.0.0.1"}),
                    PlanStep(tool="nmap", action="port_scan", params={"target": "10.0.0.1"}),
                ),
            ),
            results=(
                StepResult(
                    tool="http",
                    action="http_ip_probe",
                    ok=True,
                    payload={
                        "target": "10.0.0.1",
                        "mode": "http_ip_probe",
                        "provider": "custom",
                        "findings": [
                            {
                                "url": "http://10.0.0.1",
                                "status_code": 200,
                                "title": "",
                                "redirect_to": "",
                                "headers": {},
                                "ok": True,
                                "error": "",
                            },
                            {
                                "url": "https://10.0.0.1",
                                "status_code": None,
                                "title": "",
                                "redirect_to": "",
                                "headers": {},
                                "ok": False,
                                "error": "connection timed out",
                            },
                        ],
                        "elapsed_seconds": 0.4,
                    },
                ),
                StepResult(
                    tool="nmap",
                    action="port_scan",
                    ok=True,
                    payload={
                        "command": ["nmap", "-Pn", "-T3", "-p", "1-1024", "10.0.0.1"],
                        "target": "10.0.0.1",
                        "host_status": "up",
                        "elapsed_seconds": 49.96,
                        "open_ports": 3,
                        "filtered_ports": 3,
                        "interesting_ports": 6,
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
        self.assertIn("[result] recon complete with warnings -> #NFID", output.getvalue())

    def test_handle_recon_marks_failed_dns_plus_nmap_success_as_partial(self):
        original_run_expression = recon_cmd.run_expression

        recon_cmd.run_expression = lambda expression, session, **kwargs: RunResult(
            context=ExecutionContext(expression=expression, module="recon", params={"target": "example.com"}),
            plan=ExecutionPlan(
                context=ExecutionContext(expression=expression, module="recon", params={"target": "example.com"}),
                steps=(
                    PlanStep(tool="dns", action="dns", params={"target": "example.com", "host": "example.com"}),
                    PlanStep(tool="nmap", action="port_scan", params={"target": "example.com"}),
                ),
            ),
            results=(
                StepResult(
                    tool="dns",
                    action="dns",
                    ok=False,
                    payload={
                        "target": "example.com",
                        "host": "example.com",
                        "records": {"A": [], "AAAA": [], "MX": [], "NS": []},
                        "resolved_ips": [],
                        "provider": "custom",
                        "raw_output": "",
                        "elapsed_seconds": 0.1,
                    },
                    error="dns lookup failed for example.com",
                ),
                StepResult(
                    tool="nmap",
                    action="port_scan",
                    ok=True,
                    payload={
                        "command": ["nmap", "-Pn", "-T3", "-p", "1-1024", "example.com"],
                        "target": "example.com",
                        "host_status": "up",
                        "elapsed_seconds": 12.4,
                        "open_ports": 2,
                        "filtered_ports": 0,
                        "interesting_ports": 2,
                        "ports": [
                            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
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
                ok = recon_cmd.handle_recon("recon[target=example.com]", active_job="A12F", use_color=False)
        finally:
            recon_cmd.run_expression = original_run_expression

        self.assertTrue(ok)
        text = output.getvalue()
        self.assertIn("dns  (source: custom)", text)
        self.assertIn("[result] recon partial -> #A12F", text)

    def test_handle_recon_reports_failure_when_all_steps_fail(self):
        original_run_expression = recon_cmd.run_expression

        recon_cmd.run_expression = lambda expression, session, **kwargs: RunResult(
            context=ExecutionContext(expression=expression, module="recon", params={"target": "example.com"}),
            plan=ExecutionPlan(
                context=ExecutionContext(expression=expression, module="recon", params={"target": "example.com"}),
                steps=(
                    PlanStep(tool="dns", action="dns", params={"target": "example.com", "host": "example.com"}),
                    PlanStep(tool="http", action="http_probe", params={"target": "example.com", "host": "example.com"}),
                ),
            ),
            results=(
                StepResult(
                    tool="dns",
                    action="dns",
                    ok=False,
                    payload={
                        "target": "example.com",
                        "host": "example.com",
                        "records": {"A": [], "AAAA": [], "MX": [], "NS": []},
                        "resolved_ips": [],
                        "provider": "custom",
                        "raw_output": "",
                        "elapsed_seconds": 0.1,
                    },
                    error="dns lookup failed for example.com",
                ),
                StepResult(
                    tool="http",
                    action="http_probe",
                    ok=False,
                    payload={
                        "target": "example.com",
                        "mode": "http_probe",
                        "provider": "custom",
                        "findings": [
                            {
                                "url": "https://example.com",
                                "status_code": None,
                                "title": "",
                                "redirect_to": "",
                                "headers": {},
                                "ok": False,
                                "error": "connection timed out",
                            }
                        ],
                        "elapsed_seconds": 0.4,
                    },
                    error="connection timed out",
                ),
            ),
        )

        output = io.StringIO()
        try:
            with redirect_stdout(output):
                ok = recon_cmd.handle_recon("recon[target=example.com]", active_job="A12F", use_color=False)
        finally:
            recon_cmd.run_expression = original_run_expression

        self.assertFalse(ok)
        self.assertEqual(output.getvalue().splitlines()[-1], "[error] dns lookup failed for example.com")

    def test_handle_recon_returns_partial_results_when_port_scan_times_out(self):
        original_run_expression = recon_cmd.run_expression

        recon_cmd.run_expression = lambda expression, session, **kwargs: RunResult(
            context=ExecutionContext(expression=expression, module="recon", params={"target": "example.com"}),
            plan=ExecutionPlan(
                context=ExecutionContext(expression=expression, module="recon", params={"target": "example.com"}),
                steps=(
                    PlanStep(tool="dns", action="dns", params={"target": "example.com", "host": "example.com"}),
                    PlanStep(tool="http", action="http_probe", params={"target": "example.com", "host": "example.com"}),
                    PlanStep(tool="nmap", action="port_scan", params={"target": "example.com"}),
                ),
            ),
            results=(
                StepResult(
                    tool="dns",
                    action="dns",
                    ok=True,
                    payload={
                        "target": "example.com",
                        "host": "example.com",
                        "records": {"A": ["93.184.216.34"], "AAAA": [], "MX": [], "NS": []},
                        "resolved_ips": ["93.184.216.34"],
                        "provider": "custom",
                        "raw_output": "",
                        "elapsed_seconds": 0.1,
                    },
                ),
                StepResult(
                    tool="http",
                    action="http_probe",
                    ok=True,
                    payload={
                        "target": "example.com",
                        "mode": "http_probe",
                        "provider": "custom",
                        "findings": [
                            {
                                "url": "https://example.com",
                                "status_code": 200,
                                "title": "Example Domain",
                                "redirect_to": "",
                                "headers": {},
                                "ok": True,
                                "error": "",
                            }
                        ],
                        "elapsed_seconds": 0.4,
                    },
                ),
                StepResult(
                    tool="nmap",
                    action="port_scan",
                    ok=False,
                    payload={
                        "command": ["nmap", "-Pn", "-T3", "-p", "1-1024", "example.com"],
                        "target": "example.com",
                        "host_status": "",
                        "raw_output": "",
                        "ports": [],
                        "warnings": [],
                        "open_ports": 0,
                        "filtered_ports": 0,
                        "interesting_ports": 0,
                        "elapsed_seconds": 60.0,
                    },
                    error="nmap scan timed out after 60.0 seconds",
                ),
            ),
        )

        output = io.StringIO()
        try:
            with redirect_stdout(output):
                ok = recon_cmd.handle_recon("recon[target=example.com]", active_job="A12F", use_color=False)
        finally:
            recon_cmd.run_expression = original_run_expression

        self.assertTrue(ok)
        text = output.getvalue()
        self.assertIn("dns  (source: custom)", text)
        self.assertIn("web  (source: custom)", text)
        self.assertIn("services  (source: nmap)", text)
        self.assertIn("[result] recon partial -> #A12F", text)

    def test_handle_recon_surfaces_sudo_authentication_error_for_privileged_nmap(self):
        original_run_expression = recon_cmd.run_expression

        recon_cmd.run_expression = lambda expression, session, **kwargs: RunResult(
            context=ExecutionContext(expression=expression, module="recon", params={"target": "10.0.0.1"}),
            plan=ExecutionPlan(
                context=ExecutionContext(expression=expression, module="recon", params={"target": "10.0.0.1"}),
                steps=(
                    PlanStep(tool="ipintel", action="ipintel", params={"target": "10.0.0.1", "host": "10.0.0.1"}),
                    PlanStep(tool="http", action="http_ip_probe", params={"target": "10.0.0.1", "host": "10.0.0.1"}),
                    PlanStep(tool="nmap", action="port_scan", params={"target": "10.0.0.1"}),
                ),
            ),
            results=(
                StepResult(
                    tool="ipintel",
                    action="ipintel",
                    ok=True,
                    payload={
                        "target": "10.0.0.1",
                        "lookup_ip": "10.0.0.1",
                        "asn": "AS-PRIVATE",
                        "org": "Private Network",
                        "location": "private / internal",
                        "latency": 4.3,
                        "vpn_likely": False,
                        "confidence": "low",
                        "jitter": None,
                        "bandwidth": None,
                        "mss": None,
                        "trace": [],
                        "provider": "local",
                        "raw": {},
                        "elapsed_seconds": 0.1,
                    },
                ),
                StepResult(
                    tool="http",
                    action="http_ip_probe",
                    ok=True,
                    payload={
                        "target": "10.0.0.1",
                        "mode": "http_ip_probe",
                        "provider": "custom",
                        "findings": [
                            {
                                "url": "http://10.0.0.1",
                                "status_code": 200,
                                "title": "XFINITY",
                                "redirect_to": "",
                                "headers": {},
                                "ok": True,
                                "error": "",
                            }
                        ],
                        "elapsed_seconds": 0.4,
                    },
                ),
                StepResult(
                    tool="nmap",
                    action="port_scan",
                    ok=False,
                    payload={
                        "command": ["sudo", "nmap", "-Pn", "-sS", "-T2", "--max-retries", "2", "--top-ports", "20", "10.0.0.1"],
                        "target": "10.0.0.1",
                        "host_status": "",
                        "raw_output": "",
                        "ports": [],
                        "warnings": [],
                        "open_ports": 0,
                        "filtered_ports": 0,
                        "interesting_ports": 0,
                        "elapsed_seconds": 0.1,
                    },
                    error="sudo authentication required for this scan; run 'sudo -v' and retry",
                ),
            ),
        )

        output = io.StringIO()
        try:
            with redirect_stdout(output):
                ok = recon_cmd.handle_recon(
                    "recon[target=10.0.0.1,strategy=quiet,top_ports=20]",
                    active_job="9HTV",
                    use_color=False,
                )
        finally:
            recon_cmd.run_expression = original_run_expression

        self.assertTrue(ok)
        text = output.getvalue()
        self.assertIn("services  (source: nmap)", text)
        self.assertNotIn("sudo nmap", text)
        self.assertNotIn("No open ports found.", text)
        self.assertIn("[result] recon partial -> #9HTV", text)

    def test_handle_recon_persists_partial_job_on_cancellation(self):
        original_run_expression = recon_cmd.run_expression
        state = ShellState()

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            with redirect_stdout(io.StringIO()):
                handle_new(
                    "recon[target=10.0.0.1]",
                    state,
                    jobs_root=jobs_root,
                    job_id="A12F",
                    use_color=False,
                )

            recon_cmd.run_expression = lambda expression, session, **kwargs: RunResult(
                context=ExecutionContext(expression=expression, module="recon", params={"target": "10.0.0.1"}),
                plan=ExecutionPlan(
                    context=ExecutionContext(expression=expression, module="recon", params={"target": "10.0.0.1"}),
                    steps=(PlanStep(tool="ipintel", action="ipintel", params={"target": "10.0.0.1", "host": "10.0.0.1"}),),
                ),
                results=(
                    StepResult(
                        tool="ipintel",
                        action="ipintel",
                        ok=True,
                        payload={
                            "target": "10.0.0.1",
                            "lookup_ip": "10.0.0.1",
                            "asn": "AS-PRIVATE",
                            "org": "Private Network",
                            "location": "private / internal",
                            "latency": 1.0,
                            "vpn_likely": False,
                            "confidence": "low",
                            "jitter": None,
                            "bandwidth": None,
                            "trace": [],
                            "provider": "local",
                            "elapsed_seconds": 0.2,
                        },
                    ),
                ),
                cancelled=True,
                cancellation_reason="recon cancelled by user",
            )

            output = io.StringIO()
            try:
                with redirect_stdout(output):
                    ok = recon_cmd.handle_recon(
                        "recon[target=10.0.0.1]",
                        active_job="A12F",
                        jobs_root=jobs_root,
                        use_color=False,
                    )
            finally:
                recon_cmd.run_expression = original_run_expression

            job = load_job("A12F", jobs_root)

        self.assertTrue(ok)
        assert job is not None
        self.assertEqual(job.status, "partial")
        self.assertEqual(job.summary["completed_steps"], 1)
        self.assertEqual(job.summary["failed_steps"], 1)
        self.assertIn("[warn] recon cancelled by user", output.getvalue())
        self.assertIn("[result] recon partial -> #A12F", output.getvalue())

    def test_render_ports_table_includes_filtered_ports_when_raw_output_is_missing(self):
        output = io.StringIO()

        with redirect_stdout(output):
            recon_cmd.render_ports_table(
                [
                    {"port": 22, "protocol": "tcp", "state": "filtered", "service": "ssh"},
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                ],
                use_color=False,
            )

        text = output.getvalue()
        self.assertIn("PORT    STATE SERVICE", text)
        self.assertIn("22/tcp  filtered ssh", text)
        self.assertIn("80/tcp  open     http", text)

    def test_handle_recon_fails_soft_when_engine_returns_no_results(self):
        original_run_expression = recon_cmd.run_expression

        recon_cmd.run_expression = lambda expression, session, **kwargs: RunResult(
            context=ExecutionContext(expression=expression, module="recon", params={"target": "192.168.1.1"}),
            plan=ExecutionPlan(
                context=ExecutionContext(expression=expression, module="recon", params={"target": "192.168.1.1"}),
                steps=(PlanStep(tool="nmap", action="scan", params={"target": "192.168.1.1"}),),
            ),
            results=(),
        )

        output = io.StringIO()
        try:
            with redirect_stdout(output):
                ok = recon_cmd.handle_recon("recon[target=192.168.1.1]", use_color=False)
        finally:
            recon_cmd.run_expression = original_run_expression

        self.assertFalse(ok)
        self.assertEqual(output.getvalue().strip(), "[error] recon produced no results")

    def test_validate_recon_expression_reports_unavailable_config(self):
        original_get_tool_config = recon_cmd.get_tool_config

        recon_cmd.get_tool_config = lambda name: {}
        try:
            message = recon_cmd.validate_recon_expression("recon[target=192.168.1.1]")
        finally:
            recon_cmd.get_tool_config = original_get_tool_config

        self.assertEqual(message, "recon configuration unavailable")

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
