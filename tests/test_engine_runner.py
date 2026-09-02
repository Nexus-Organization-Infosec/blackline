import unittest
from types import SimpleNamespace
import threading
import time

from blackline.core.recon.models import ReconTarget
from blackline.engine.executor import ExecutionControl, execute_plan
from blackline.engine.planner import ExecutionPlan, PlanStep, build_plan
from blackline.engine.runner import normalize_expression, parse_expression, run_expression
from blackline.engine.context import ExecutionContext
from blackline.engine.session import EngineSession
from blackline.utils.exec import CommandResult


class EngineRunnerTests(unittest.TestCase):
    def setUp(self):
        self._original_inspect_tls = execute_plan.__globals__["inspect_tls"]
        self._original_fingerprint_http = execute_plan.__globals__["fingerprint_http"]
        self._original_resolve_rdap = execute_plan.__globals__["resolve_rdap"]
        execute_plan.__globals__["inspect_tls"] = lambda host, **kwargs: SimpleNamespace(
            ok=True,
            host=host,
            port=kwargs.get("port", 443),
            subject="CN = example.test",
            issuer="CN = Test CA",
            sans=("DNS:example.test",),
            not_before="2026-01-01T00:00:00+00:00",
            not_after="2027-01-01T00:00:00+00:00",
            days_until_expiry=100,
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            certificate_sha256="a" * 64,
            provider="python ssl",
            certificate_parser="openssl",
            warnings=(),
            raw_output="",
            error="",
            elapsed_seconds=0.1,
        )
        execute_plan.__globals__["fingerprint_http"] = lambda target, **kwargs: SimpleNamespace(
            ok=True,
            target=target,
            server="nginx",
            framework="Next.js",
            cms="unknown",
            javascript="React",
            security_headers=("HSTS", "CSP"),
            cookies=("session",),
            confidence="high",
            evidence=("server header", "Next.js marker"),
            provider="urllib",
            skipped=False,
            warnings=(),
            error="",
            elapsed_seconds=0.1,
        )
        execute_plan.__globals__["resolve_rdap"] = lambda domain="", address="", **kwargs: SimpleNamespace(
            ok=True,
            domain=domain,
            registrar="Example Registrar",
            created="2020-01-01T00:00:00Z",
            expires="2030-01-01T00:00:00Z",
            status=("active",),
            address=address,
            network="EXAMPLE-NET (192.0.2.0 – 192.0.2.255)",
            organization="Example Networks, Inc.",
            asn="AS64500",
            provider="rdap.org",
            warnings=(),
            raw={},
            error="",
            elapsed_seconds=0.1,
        )

    def tearDown(self):
        execute_plan.__globals__["inspect_tls"] = self._original_inspect_tls
        execute_plan.__globals__["fingerprint_http"] = self._original_fingerprint_http
        execute_plan.__globals__["resolve_rdap"] = self._original_resolve_rdap

    def test_execute_plan_emits_step_progress(self):
        context = ExecutionContext(expression="unknown", module="unknown")
        plan = ExecutionPlan(
            context=context,
            steps=(PlanStep(tool="unknown", action="check"),),
        )
        events = []

        results = execute_plan(plan, progress_callback=events.append)

        self.assertEqual(len(results), 1)
        self.assertEqual([event.state for event in events], ["started", "completed"])
        self.assertEqual(events[0].completed, 0)
        self.assertEqual(events[1].completed, 1)
        self.assertEqual(events[1].total, 1)
        self.assertEqual(events[1].step.action, "check")
        self.assertIs(events[1].result, results[0])

    def test_parse_expression_extracts_module_and_params(self):
        context = parse_expression("recon[target=192.168.1.1,ports=80-443]", job_id="A12F")

        self.assertEqual(
            context,
            ExecutionContext(
                expression="recon[target=192.168.1.1,ports=80-443]",
                module="recon",
                params={"target": "192.168.1.1", "ports": "80-443"},
                job_id="A12F",
                normalized_target=ReconTarget(raw="192.168.1.1", target_type="ip", host="192.168.1.1"),
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
                normalized_target=ReconTarget(raw="192.168.1.1", target_type="ip", host="192.168.1.1"),
            )
        )

        self.assertEqual(len(plan.steps), 6)
        self.assertIsNotNone(plan.pipeline)
        self.assertEqual(
            [step.name for step in plan.pipeline.steps],
            ["reverse_dns", "ipintel", "http_ip_probe", "web_fingerprint", "tls_inspection", "rdap", "port_scan"],
        )
        self.assertEqual([step.tool for step in plan.steps], ["ipintel", "http", "fingerprint", "tls", "rdap", "nmap"])
        self.assertEqual(plan.steps[0].params["host"], "192.168.1.1")
        self.assertEqual(plan.steps[1].action, "http_ip_probe")
        self.assertEqual(plan.steps[1].params["host"], "192.168.1.1")
        self.assertEqual(plan.steps[2].action, "web_fingerprint")
        self.assertEqual(plan.steps[3].params["port"], "443")
        self.assertEqual(plan.steps[4].action, "rdap")
        self.assertEqual(plan.steps[5].params["target"], "192.168.1.1")
        self.assertEqual(plan.steps[5].params["ports"], "1-1024")
        self.assertEqual([step.execution_group for step in plan.steps], [0, 0, 1, 0, 2, 1])

    def test_build_plan_uses_normalized_url_host_for_recon(self):
        plan = build_plan(
            ExecutionContext(
                expression="recon[target=https://example.com/login]",
                module="recon",
                params={"target": "https://example.com/login"},
                normalized_target=ReconTarget(
                    raw="https://example.com/login",
                    target_type="url",
                    host="example.com",
                    scheme="https",
                    path="/login",
                ),
            )
        )

        self.assertEqual(len(plan.steps), 7)
        self.assertEqual([step.tool for step in plan.steps], ["http", "fingerprint", "dns", "ipintel", "tls", "rdap", "nmap"])
        self.assertEqual(plan.steps[0].action, "http_probe")
        self.assertEqual(plan.steps[0].params["scheme"], "https")
        self.assertEqual(plan.steps[0].params["path"], "/login")
        self.assertEqual(plan.steps[0].params["host"], "example.com")
        self.assertEqual(plan.steps[1].params["host"], "example.com")
        self.assertEqual(plan.steps[2].params["host"], "example.com")
        self.assertEqual(plan.steps[3].params["host"], "example.com")
        self.assertEqual(plan.steps[4].params["server_name"], "example.com")
        self.assertEqual(plan.steps[5].params["host"], "example.com")
        self.assertEqual(plan.steps[6].params["target"], "example.com")
        self.assertEqual([step.execution_group for step in plan.steps], [0, 1, 0, 1, 0, 2, 2])
        self.assertIsNotNone(plan.pipeline)
        self.assertEqual(
            [step.name for step in plan.pipeline.steps],
            ["http_probe", "web_fingerprint", "dns", "ipintel", "tls_inspection", "rdap", "port_scan"],
        )

    def test_build_plan_for_domain_includes_dns_then_nmap(self):
        plan = build_plan(
            ExecutionContext(
                expression="recon[target=example.com]",
                module="recon",
                params={"target": "example.com"},
                normalized_target=ReconTarget(raw="example.com", target_type="domain", host="example.com"),
            )
        )

        self.assertEqual([step.tool for step in plan.steps], ["dns", "ipintel", "http", "fingerprint", "tls", "rdap", "nmap"])
        self.assertEqual(plan.steps[0].action, "dns")
        self.assertEqual(plan.steps[0].params["host"], "example.com")
        self.assertEqual(plan.steps[1].action, "ipintel")
        self.assertEqual(plan.steps[2].action, "http_probe")
        self.assertEqual(plan.steps[3].action, "web_fingerprint")
        self.assertEqual(plan.steps[4].action, "tls_inspection")
        self.assertEqual(plan.steps[5].action, "rdap")
        self.assertEqual(plan.steps[6].action, "port_scan")
        self.assertEqual(plan.steps[6].params["target"], "example.com")
        self.assertEqual([step.execution_group for step in plan.steps], [0, 1, 0, 1, 0, 2, 2])

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
                normalized_target=ReconTarget(raw="192.168.1.1", target_type="ip", host="192.168.1.1"),
            )
        )

        self.assertEqual([step.tool for step in plan.steps], ["ipintel", "http", "fingerprint", "tls", "rdap", "nmap"])
        self.assertEqual(plan.steps[5].params["profile"], "stealth")
        self.assertIsNotNone(plan.pipeline)
        self.assertEqual(
            [step.name for step in plan.pipeline.steps],
            ["reverse_dns", "ipintel", "http_ip_probe", "web_fingerprint", "tls_inspection", "rdap", "port_scan"],
        )
        self.assertEqual(plan.steps[5].params["top_ports"], "20")
        self.assertEqual(plan.steps[5].params["timing"], "T4")
        self.assertEqual(plan.steps[5].params["service_detection"], "true")
        self.assertEqual([step.execution_group for step in plan.steps], [0, 0, 1, 0, 2, 1])

    def test_execute_plan_returns_structured_results(self):
        plan = build_plan(
            ExecutionContext(
                expression="recon[target=192.168.1.1]",
                module="recon",
                params={"target": "192.168.1.1"},
                normalized_target=ReconTarget(raw="192.168.1.1", target_type="ip", host="192.168.1.1"),
            )
        )

        calls = {"count": 0}
        original_probe_http = execute_plan.__globals__["probe_http"]

        class FakeHttpResult:
            def __init__(self) -> None:
                self.ok = True
                self.target = "192.168.1.1"
                self.mode = "http_ip_probe"
                self.provider = "custom"
                self.error = ""
                self.elapsed_seconds = 0.2
                self.findings = []

        def fake_executor(args: tuple[str, ...]) -> CommandResult:
            calls["count"] += 1
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

        execute_plan.__globals__["probe_http"] = lambda *args, **kwargs: FakeHttpResult()
        try:
            results = execute_plan(plan, command_executor=fake_executor)
        finally:
            execute_plan.__globals__["probe_http"] = original_probe_http

        self.assertEqual(len(results), 6)
        self.assertTrue(results[0].ok)
        self.assertEqual(results[0].tool, "ipintel")
        self.assertEqual(results[0].payload["lookup_ip"], "192.168.1.1")
        self.assertEqual(results[1].tool, "http")
        self.assertEqual(results[1].payload["mode"], "http_ip_probe")
        self.assertEqual(results[2].tool, "fingerprint")
        self.assertEqual(results[2].payload["framework"], "Next.js")
        self.assertEqual(results[3].tool, "tls")
        self.assertEqual(results[3].payload["protocol"], "TLSv1.3")
        self.assertEqual(results[4].tool, "rdap")
        self.assertEqual(results[4].payload["asn"], "AS64500")
        self.assertEqual(results[5].payload["target"], "192.168.1.1")
        self.assertEqual(
            results[5].payload["ports"],
            [
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
            ],
        )
        self.assertEqual(results[5].payload["open_ports"], 2)
        self.assertEqual(results[5].payload["filtered_ports"], 0)
        self.assertEqual(results[5].payload["interesting_ports"], 2)
        self.assertEqual(results[5].payload["elapsed_seconds"], 41.2)
        self.assertEqual(calls["count"], 1)

    def test_execute_plan_parallelizes_independent_fast_ip_steps_but_keeps_result_order(self):
        plan = build_plan(
            ExecutionContext(
                expression="recon[target=192.168.1.1]",
                module="recon",
                params={"target": "192.168.1.1"},
                normalized_target=ReconTarget(raw="192.168.1.1", target_type="ip", host="192.168.1.1"),
            )
        )

        original_probe_http = execute_plan.__globals__["probe_http"]
        original_resolve_ipintel = execute_plan.__globals__["resolve_ipintel"]
        dns_started = threading.Event()
        http_started = threading.Event()
        overlap = {"ipintel_saw_http": False, "http_saw_ipintel": False}

        class FakeHttpResult:
            def __init__(self) -> None:
                self.ok = True
                self.target = "192.168.1.1"
                self.mode = "http_ip_probe"
                self.provider = "custom"
                self.error = ""
                self.elapsed_seconds = 0.2
                self.findings = []

        def fake_resolve_ipintel(target: str, lookup_ip: str = "", deep: bool = False):
            dns_started.set()
            overlap["ipintel_saw_http"] = http_started.wait(0.15)
            time.sleep(0.02)
            return SimpleNamespace(
                ok=True,
                target=target,
                lookup_ip=lookup_ip or target,
                asn="AS-PRIVATE",
                org="Private Network",
                location="private / internal",
                latency=1.0,
                vpn_likely=False,
                confidence="low",
                jitter=None,
                bandwidth=None,
                trace=[],
                provider="custom",
                error="",
            )

        def fake_probe_http(*args, **kwargs):
            http_started.set()
            overlap["http_saw_ipintel"] = dns_started.wait(0.15)
            time.sleep(0.02)
            return FakeHttpResult()

        def fake_executor(args: tuple[str, ...]) -> CommandResult:
            return CommandResult(
                args=args,
                returncode=0,
                stdout="Nmap scan report for 192.168.1.1\nHost is up.\n22/tcp open ssh\n",
                stderr="",
                elapsed_seconds=1.0,
            )

        execute_plan.__globals__["probe_http"] = fake_probe_http
        execute_plan.__globals__["resolve_ipintel"] = fake_resolve_ipintel
        try:
            results = execute_plan(plan, command_executor=fake_executor)
        finally:
            execute_plan.__globals__["probe_http"] = original_probe_http
            execute_plan.__globals__["resolve_ipintel"] = original_resolve_ipintel

        self.assertTrue(overlap["ipintel_saw_http"])
        self.assertTrue(overlap["http_saw_ipintel"])
        self.assertEqual([result.tool for result in results], ["ipintel", "http", "fingerprint", "tls", "rdap", "nmap"])

    def test_execute_plan_keeps_domain_result_order_stable_even_when_http_finishes_first(self):
        plan = build_plan(
            ExecutionContext(
                expression="recon[target=example.com]",
                module="recon",
                params={"target": "example.com"},
                normalized_target=ReconTarget(raw="example.com", target_type="domain", host="example.com"),
            )
        )

        original_resolve_dns = execute_plan.__globals__["resolve_dns"]
        original_probe_http = execute_plan.__globals__["probe_http"]
        original_resolve_ipintel = execute_plan.__globals__["resolve_ipintel"]

        execute_plan.__globals__["resolve_dns"] = lambda host, command_executor=None: SimpleNamespace(
            ok=True,
            host=host,
            records={"A": ["93.184.216.34"], "AAAA": [], "MX": [], "NS": []},
            resolved_ips=["93.184.216.34"],
            provider="custom",
            raw_output="",
            error="",
            elapsed_seconds=0.2,
        )

        def fake_probe_http(*args, **kwargs):
            time.sleep(0.01)
            return SimpleNamespace(
                ok=True,
                provider="custom",
                error="",
                elapsed_seconds=0.05,
                findings=[],
            )

        execute_plan.__globals__["probe_http"] = fake_probe_http
        execute_plan.__globals__["resolve_ipintel"] = lambda target, lookup_ip="", deep=False: SimpleNamespace(
            ok=True,
            target=target,
            lookup_ip=lookup_ip,
            asn="AS15169",
            org="Example Org",
            location="US / NY / New York",
            latency=19.8,
            vpn_likely=False,
            confidence="high",
            jitter=None,
            bandwidth=None,
            trace=[],
            provider="custom",
            error="",
        )

        def fake_executor(args: tuple[str, ...]) -> CommandResult:
            return CommandResult(
                args=args,
                returncode=0,
                stdout="Nmap scan report for example.com\nHost is up.\n80/tcp open http\n",
                stderr="",
                elapsed_seconds=1.0,
            )

        try:
            results = execute_plan(plan, command_executor=fake_executor)
        finally:
            execute_plan.__globals__["resolve_dns"] = original_resolve_dns
            execute_plan.__globals__["probe_http"] = original_probe_http
            execute_plan.__globals__["resolve_ipintel"] = original_resolve_ipintel

        self.assertEqual([result.tool for result in results], ["dns", "ipintel", "http", "fingerprint", "tls", "rdap", "nmap"])
        self.assertEqual(results[1].payload["lookup_ip"], "93.184.216.34")

    def test_run_expression_tracks_session_runs(self):
        session = EngineSession(active_job="A12F")
        original_probe_http = run_expression.__globals__["execute_plan"].__globals__["probe_http"]

        class FakeHttpResult:
            def __init__(self) -> None:
                self.ok = True
                self.target = "192.168.1.1"
                self.mode = "http_ip_probe"
                self.provider = "custom"
                self.error = ""
                self.elapsed_seconds = 0.1
                self.findings = []

        def fake_executor(args: tuple[str, ...]) -> CommandResult:
            return CommandResult(
                args=args,
                returncode=0,
                stdout="Nmap scan report for 192.168.1.1\nHost is up.\n22/tcp open ssh\n",
                stderr="",
                elapsed_seconds=15.5,
            )

        run_expression.__globals__["execute_plan"].__globals__["probe_http"] = lambda *args, **kwargs: FakeHttpResult()
        try:
            result = run_expression(
                "recon[target=192.168.1.1]",
                session=session,
                command_executor=fake_executor,
            )
        finally:
            run_expression.__globals__["execute_plan"].__globals__["probe_http"] = original_probe_http

        self.assertTrue(result.ok)
        self.assertEqual(result.context.job_id, "A12F")
        self.assertEqual(result.context.normalized_target, ReconTarget(raw="192.168.1.1", target_type="ip", host="192.168.1.1"))
        self.assertEqual(session.runs, ["recon[target=192.168.1.1]"])

    def test_execute_plan_returns_partial_results_when_scan_is_cancelled(self):
        plan = build_plan(
            ExecutionContext(
                expression="recon[target=192.168.1.1]",
                module="recon",
                params={"target": "192.168.1.1"},
                normalized_target=ReconTarget(raw="192.168.1.1", target_type="ip", host="192.168.1.1"),
            )
        )

        original_probe_http = execute_plan.__globals__["probe_http"]
        control = ExecutionControl()

        class FakeHttpResult:
            def __init__(self) -> None:
                self.ok = True
                self.target = "192.168.1.1"
                self.mode = "http_ip_probe"
                self.provider = "custom"
                self.error = ""
                self.elapsed_seconds = 0.2
                self.findings = []

        def fake_executor(args: tuple[str, ...]) -> CommandResult:
            raise KeyboardInterrupt

        execute_plan.__globals__["probe_http"] = lambda *args, **kwargs: FakeHttpResult()
        try:
            results = execute_plan(plan, command_executor=fake_executor, control=control)
        finally:
            execute_plan.__globals__["probe_http"] = original_probe_http

        self.assertEqual(len(results), 3)
        self.assertEqual([result.tool for result in results], ["ipintel", "http", "tls"])
        self.assertTrue(control.cancelled)
        self.assertEqual(control.cancellation_reason, "recon cancelled by user")

    def test_run_expression_exposes_cancellation_state(self):
        session = EngineSession(active_job="A12F")
        original_probe_http = run_expression.__globals__["execute_plan"].__globals__["probe_http"]

        class FakeHttpResult:
            def __init__(self) -> None:
                self.ok = True
                self.target = "192.168.1.1"
                self.mode = "http_ip_probe"
                self.provider = "custom"
                self.error = ""
                self.elapsed_seconds = 0.2
                self.findings = []

        def fake_executor(args: tuple[str, ...]) -> CommandResult:
            raise KeyboardInterrupt

        run_expression.__globals__["execute_plan"].__globals__["probe_http"] = lambda *args, **kwargs: FakeHttpResult()
        try:
            result = run_expression(
                "recon[target=192.168.1.1]",
                session=session,
                command_executor=fake_executor,
            )
        finally:
            run_expression.__globals__["execute_plan"].__globals__["probe_http"] = original_probe_http

        self.assertFalse(result.ok)
        self.assertTrue(result.cancelled)
        self.assertEqual(result.cancellation_reason, "recon cancelled by user")
        self.assertEqual([step.tool for step in result.results], ["ipintel", "http", "tls"])

    def test_execute_plan_uses_configured_port_scan_timeout(self):
        plan = build_plan(
            ExecutionContext(
                expression="recon[target=192.168.1.1]",
                module="recon",
                params={"target": "192.168.1.1"},
                normalized_target=ReconTarget(raw="192.168.1.1", target_type="ip", host="192.168.1.1"),
            )
        )

        original_probe_http = execute_plan.__globals__["probe_http"]
        original_execute_nmap = execute_plan.__globals__["execute_nmap"]
        original_get_tool_config = execute_plan.__globals__["get_tool_config"]
        captured = {"timeout_seconds": None}

        class FakeHttpResult:
            def __init__(self) -> None:
                self.ok = True
                self.target = "192.168.1.1"
                self.mode = "http_ip_probe"
                self.provider = "custom"
                self.error = ""
                self.elapsed_seconds = 0.2
                self.findings = []

        def fake_execute_nmap(*args, **kwargs):
            captured["timeout_seconds"] = kwargs.get("timeout_seconds")
            return SimpleNamespace(
                ok=False,
                command=("nmap", "192.168.1.1"),
                parsed=SimpleNamespace(target="192.168.1.1", host_status="", raw_output="", ports=[], warnings=[]),
                elapsed_seconds=1.0,
                error="nmap scan timed out after 5.0 seconds",
                stderr="command timed out after 5.0 seconds",
            )

        execute_plan.__globals__["probe_http"] = lambda *args, **kwargs: FakeHttpResult()
        execute_plan.__globals__["execute_nmap"] = fake_execute_nmap
        execute_plan.__globals__["get_tool_config"] = lambda name: {
            "execution_control": {"timeouts": {"port_scan_seconds": 5}}
        } if name == "recon" else {}
        try:
            results = execute_plan(plan)
        finally:
            execute_plan.__globals__["probe_http"] = original_probe_http
            execute_plan.__globals__["execute_nmap"] = original_execute_nmap
            execute_plan.__globals__["get_tool_config"] = original_get_tool_config

        self.assertEqual(captured["timeout_seconds"], 5.0)
        self.assertEqual(results[-1].error, "nmap scan timed out after 5.0 seconds")


if __name__ == "__main__":
    unittest.main()
