import io
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

from blackline.cli.commands.recon import recon_cmd
from blackline.cli.commands.system.jobs_cmd import handle_new, load_job
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.core.recon.models import ReconTarget
from blackline.core.recon.steps.ipintel import execute_ipintel_step
from blackline.engine.executor import StepResult, execute_plan
from blackline.engine.planner import PlanStep, ExecutionPlan
from blackline.tools.parsers.yougotmapped import parse_yougotmapped_json
from blackline.tools.intel import yougotmapped


class IpIntelTests(unittest.TestCase):
    def test_build_yougotmapped_command_uses_configured_flags(self):
        command = yougotmapped.build_yougotmapped_command(
            "8.8.8.8",
            deep=False,
            output_path="/tmp/ygm.json",
            config={
                "binary": "yougotmapped",
                "defaults": {
                    "no_map": True,
                    "default_flags": ["-p", "-c"],
                    "deep_flags": ["-a"],
                },
            },
        )

        self.assertEqual(
            command,
            ("yougotmapped", "-i", "8.8.8.8", "-p", "-c", "--no-map", "-o", "/tmp/ygm.json"),
        )

    def test_parse_yougotmapped_json_returns_structured_result(self):
        parsed = parse_yougotmapped_json(
            [
                {
                    "ip": "8.8.8.8",
                    "org": "Google LLC",
                    "country": "United States",
                    "region": "California",
                    "city": "Mountain View",
                    "raw": {
                        "country_code": "US",
                        "region_code": "CA",
                        "city": "Mountain View",
                        "connection": {
                            "asn": 15169,
                            "org": "Google LLC",
                            "domain": "google.com",
                        },
                    },
                    "ping": {
                        "reachable": True,
                        "rtt_ms": {"min": 12.38, "avg": 17.98, "median": 18.84, "max": 21.64},
                    },
                    "jitter": {
                        "reachable": True,
                        "jitter_ms": 6.36,
                    },
                    "mss": {
                        "reachable": True,
                        "mss": 1460,
                    },
                    "bandwidth": {
                        "available": True,
                        "estimated_mbps": 0.62,
                    },
                    "traceroute": {
                        "hops": [
                            {"hop": 1, "ip": "10.0.0.1", "private": True, "rtt_ms": [3.2]},
                            {"hop": 20, "ip": "8.8.8.8", "private": False, "rtt_ms": [25.4]},
                        ]
                    },
                    "anonymity": {
                        "vpn": True,
                        "confidence": "high",
                    },
                }
            ]
        )

        self.assertTrue(parsed.ok)
        self.assertEqual(parsed.lookup_ip, "8.8.8.8")
        self.assertEqual(parsed.asn, "AS15169")
        self.assertEqual(parsed.org, "Google LLC")
        self.assertEqual(parsed.domain, "google.com")
        self.assertEqual(parsed.location, "US / CA / Mountain View")
        self.assertEqual(parsed.latency, 17.98)
        self.assertEqual(parsed.jitter, 6.36)
        self.assertEqual(parsed.bandwidth, 0.62)
        self.assertEqual(parsed.mss, 1460)
        self.assertTrue(parsed.vpn_likely)
        self.assertEqual(parsed.confidence, "high")
        self.assertEqual(parsed.trace[0], "[ 1] 10.0.0.1        PRIVATE 3.2 ms")

    def test_resolve_ipintel_with_custom_provider_returns_structured_result(self):
        result = yougotmapped.resolve_ipintel(
            "example.com",
            lookup_ip="8.8.8.8",
            provider=lambda lookup_ip, deep: {
                "asn": "AS15169",
                "org": "Google LLC",
                "location": "US / CA / Mountain View",
                "latency": 19.8,
                "vpn_likely": True,
                "confidence": "high",
                "jitter": 5.9 if deep else None,
                "bandwidth": 0.64 if deep else None,
                "trace": ["1 10.0.0.1", "22 8.8.8.8"] if deep else [],
                "provider": "custom",
            },
            deep=True,
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.lookup_ip, "8.8.8.8")
        self.assertEqual(result.asn, "AS15169")
        self.assertEqual(result.org, "Google LLC")
        self.assertEqual(result.location, "US / CA / Mountain View")
        self.assertTrue(result.vpn_likely)
        self.assertEqual(result.confidence, "high")
        self.assertEqual(result.trace[-1], "22 8.8.8.8")

    def test_execute_ipintel_step_supports_private_ip_default(self):
        result = execute_ipintel_step(
            ReconTarget(raw="10.0.0.1", target_type="ip", host="10.0.0.1"),
            lookup_ip="10.0.0.1",
            deep=False,
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.asn, "AS-PRIVATE")
        self.assertEqual(result.org, "Private Network")
        self.assertEqual(result.location, "private / internal")

    def test_execute_plan_uses_dns_resolved_ip_for_ipintel(self):
        plan = ExecutionPlan(
            context=None,  # type: ignore[arg-type]
            steps=(
                PlanStep(tool="dns", action="dns", params={"target": "example.com", "host": "example.com"}),
                PlanStep(tool="ipintel", action="ipintel", params={"target": "example.com", "host": "example.com", "target_type": "domain", "deep": ""}),
            ),
        )

        original_resolve_dns = execute_plan.__globals__["resolve_dns"]
        original_resolve_ipintel = execute_plan.__globals__["resolve_ipintel"]
        execute_plan.__globals__["resolve_dns"] = lambda host, command_executor=None: __import__(
            "blackline.tools.dns.resolver", fromlist=["DnsLookupResult"]
        ).DnsLookupResult(
            ok=True,
            host=host,
            records={"A": ["93.184.216.34"], "AAAA": [], "MX": [], "NS": []},
            resolved_ips=["93.184.216.34"],
            provider="custom",
        )
        execute_plan.__globals__["resolve_ipintel"] = lambda target, lookup_ip="", deep=False: yougotmapped.IpIntelResult(
            ok=True,
            target=target,
            lookup_ip=lookup_ip,
            asn="AS15169",
            org="Example Org",
            location="US / NY / New York",
            latency=19.8,
            vpn_likely=False,
            confidence="high",
            provider="custom",
        )
        try:
            results = execute_plan(plan)
        finally:
            execute_plan.__globals__["resolve_dns"] = original_resolve_dns
            execute_plan.__globals__["resolve_ipintel"] = original_resolve_ipintel

        self.assertEqual(results[1].tool, "ipintel")
        self.assertEqual(results[1].payload["lookup_ip"], "93.184.216.34")
        self.assertEqual(results[1].payload["asn"], "AS15169")

    def test_record_job_result_updates_ipintel_block(self):
        state = ShellState()
        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            with redirect_stdout(io.StringIO()):
                handle_new(
                    "recon[target=10.0.0.1]",
                    state,
                    jobs_root=jobs_root,
                    created_at=datetime(2026, 4, 23, 10, 32),
                    job_id="A12F",
                    use_color=False,
                )

            recon_cmd.record_job_result(
                "A12F",
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
                {
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
                jobs_root=jobs_root,
            )

            job = load_job("A12F", jobs_root)

        self.assertIsNotNone(job)
        assert job is not None
        self.assertEqual(job.ipintel["asn"], "AS-PRIVATE")
        self.assertEqual(job.ipintel["org"], "Private Network")
        self.assertEqual(job.ipintel["lookup_ip"], "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
