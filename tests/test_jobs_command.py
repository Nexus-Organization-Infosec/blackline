import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

from blackline.cli.commands.system.jobs_cmd import (
    append_job_result,
    handle_delete_job,
    handle_enter,
    handle_jobs,
    handle_leave_job,
    handle_new,
    handle_show,
    list_job_ids,
    load_job,
    parse_delete_targets,
    parse_job_expression,
)
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.cli.core_shell import dispatch_line


class JobsCommandTests(unittest.TestCase):
    def _job_with_evidence(self, jobs_root: Path) -> ShellState:
        state = ShellState()
        with redirect_stdout(io.StringIO()):
            handle_new("recon[target=example.com]", state, jobs_root=jobs_root, job_id="A12F", use_color=False)
        append_job_result(
            "A12F",
            {
                "module": "recon",
                "tool": "dns",
                "action": "dns",
                "ok": True,
                "error": "",
                "payload": {"provider": "dnspython", "records": {"A": ["192.0.2.10"]}, "raw_output": "DNS raw artifact", "elapsed_seconds": 0.1},
            },
            jobs_root=jobs_root,
        )
        append_job_result(
            "A12F",
            {
                "module": "recon",
                "tool": "tls",
                "action": "tls_inspection",
                "ok": True,
                "error": "",
                "payload": {"provider": "python ssl", "certificate_parser": "openssl", "host": "example.com", "port": 443, "protocol": "TLSv1.3", "elapsed_seconds": 0.1},
            },
            jobs_root=jobs_root,
        )
        append_job_result(
            "A12F",
            {
                "module": "recon",
                "tool": "evidence",
                "action": "correlation",
                "ok": True,
                "error": "",
                "payload": {"target": "example.com", "claims": [{"subject": "example.com", "predicate": "resolves_to", "value": "192.0.2.10", "sources": ["dnspython"]}], "warnings": [], "elapsed_seconds": 0.0},
            },
            jobs_root=jobs_root,
        )
        return state

    def test_show_sources_lists_provider_provenance_for_active_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            state = self._job_with_evidence(jobs_root)
            output = io.StringIO()
            with redirect_stdout(output):
                handle_show(state, "sources", jobs_root=jobs_root, use_color=False)

        text = output.getvalue()
        self.assertIn("sources", text)
        self.assertIn("dns          : dnspython", text)
        self.assertIn("tls          : python ssl, openssl", text)
        self.assertIn("evidence     : dnspython", text)

    def test_show_raw_only_prints_stored_raw_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            state = self._job_with_evidence(jobs_root)
            output = io.StringIO()
            with redirect_stdout(output):
                handle_show(state, "raw", jobs_root=jobs_root, use_color=False)

        text = output.getvalue()
        self.assertIn("raw dns", text)
        self.assertIn("DNS raw artifact", text)
        self.assertNotIn("TLSv1.3", text)

    def test_show_section_uses_curated_section_renderer_and_supports_explicit_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            state = self._job_with_evidence(jobs_root)
            output = io.StringIO()
            with redirect_stdout(output):
                handle_show(state, "#A12F tls", jobs_root=jobs_root, use_color=False)

        text = output.getvalue()
        self.assertIn("tls  (sources: python ssl, openssl)", text)
        self.assertIn("protocol   : TLSv1.3", text)
        self.assertNotIn("DNS raw artifact", text)

    def test_show_correlation_maps_the_persisted_evidence_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            state = self._job_with_evidence(jobs_root)
            output = io.StringIO()
            with redirect_stdout(output):
                handle_show(state, "correlation", jobs_root=jobs_root, use_color=False)

        self.assertIn("correlation  (source: dnspython)", output.getvalue())

    def test_show_formatted_replays_saved_final_recon_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            state = self._job_with_evidence(jobs_root)
            output = io.StringIO()
            with redirect_stdout(output):
                handle_show(state, "#A12F formatted", jobs_root=jobs_root, use_color=False)

        text = output.getvalue()
        self.assertIn("[info] target example.com", text)
        self.assertIn("dns  (source: dnspython)", text)
        self.assertIn("tls  (sources: python ssl, openssl)", text)
        self.assertIn("correlation  (source: dnspython)", text)
        self.assertIn("[result] recon complete -> #A12F", text)
        self.assertNotIn("DNS raw artifact", text)

    def test_parse_job_expression(self):
        self.assertEqual(
            parse_job_expression("recon[target=192.168.1.1,ports=80-443]"),
            ("recon", {"target": "192.168.1.1", "ports": "80-443"}),
        )

    def test_new_creates_persisted_job_and_enters_context(self):
        state = ShellState()
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            with redirect_stdout(output):
                created = handle_new(
                    "recon[target=192.168.1.1]",
                    state,
                    jobs_root=jobs_root,
                    created_at=datetime(2026, 4, 23, 10, 32),
                    job_id="A12F",
                    use_color=False,
                )

            data = json.loads((jobs_root / "A12F.json").read_text(encoding="utf-8"))

        self.assertTrue(created)
        self.assertEqual(state.active_job, "A12F")
        self.assertEqual(data["id"], "A12F")
        self.assertEqual(data["module"], "recon")
        self.assertEqual(data["params"], {"target": "192.168.1.1"})
        self.assertEqual(data["target"], "192.168.1.1")
        self.assertEqual(data["target_type"], "ip")
        self.assertEqual(data["steps"], [])
        self.assertEqual(data["summary"]["step_count"], 0)
        self.assertEqual(data["summary"]["result_count"], 0)
        self.assertEqual(data["ipintel"], {})
        text = output.getvalue()
        self.assertIn("[job]", text)
        self.assertIn("id       : #A12F", text)
        self.assertIn("module   : recon", text)
        self.assertIn("target   : 192.168.1.1", text)
        self.assertIn("type     : ip", text)
        self.assertIn("created  : 2026-04-23 10:32", text)
        self.assertIn("status   : initialized", text)
        self.assertIn("steps    : 0", text)
        self.assertIn("results  : 0", text)
        self.assertIn("[info] entered job #A12F", text)

    def test_new_without_expression_creates_manual_job(self):
        state = ShellState()
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            with redirect_stdout(output):
                created = handle_new(
                    "",
                    state,
                    jobs_root=jobs_root,
                    created_at=datetime(2026, 4, 23, 10, 32),
                    job_id="B93K",
                    use_color=False,
                )

            data = json.loads((jobs_root / "B93K.json").read_text(encoding="utf-8"))

        self.assertTrue(created)
        self.assertEqual(state.active_job, "B93K")
        self.assertEqual(data["module"], "manual")
        self.assertEqual(data["params"], {})
        text = output.getvalue()
        self.assertIn("id       : #B93K", text)
        self.assertIn("module   : manual", text)
        self.assertIn("results  : 0", text)
        self.assertIn("[info] entered job #B93K", text)

    def test_new_rejects_invalid_module(self):
        state = ShellState()
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp:
            with redirect_stdout(output):
                created = handle_new("reconx[target=1.1.1.1]", state, jobs_root=Path(tmp), use_color=False)

        self.assertFalse(created)
        self.assertEqual(state.active_job, "")
        self.assertEqual(output.getvalue().strip(), "[error] module not found: reconx")

    def test_new_recon_still_works_when_help_groups_are_unavailable(self):
        state = ShellState()
        output = io.StringIO()
        original_load_help_groups = handle_new.__globals__["load_help_groups"]

        handle_new.__globals__["load_help_groups"] = lambda: ()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                jobs_root = Path(tmp)
                with redirect_stdout(output):
                    created = handle_new(
                        "recon[target=192.168.1.1]",
                        state,
                        jobs_root=jobs_root,
                        created_at=datetime(2026, 4, 23, 10, 32),
                        job_id="A12F",
                        use_color=False,
                    )

                data = json.loads((jobs_root / "A12F.json").read_text(encoding="utf-8"))
        finally:
            handle_new.__globals__["load_help_groups"] = original_load_help_groups

        self.assertTrue(created)
        self.assertEqual(state.active_job, "A12F")
        self.assertEqual(data["module"], "recon")
        self.assertIn("[info] entered job #A12F", output.getvalue())

    def test_new_missing_args_falls_back_to_interactive_message(self):
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp:
            with redirect_stdout(output):
                created = handle_new("recon", ShellState(), jobs_root=Path(tmp), use_color=False)

        self.assertFalse(created)
        self.assertEqual(output.getvalue().strip(), "[info] missing required fields → entering interactive mode")

    def test_show_jobs_enter_and_leave(self):
        state = ShellState()
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            with redirect_stdout(io.StringIO()):
                handle_new(
                    "recon[target=192.168.1.1]",
                    state,
                    jobs_root=jobs_root,
                    created_at=datetime(2026, 4, 23, 10, 32),
                    job_id="A12F",
                    use_color=False,
                )
            state.active_job = ""

            with redirect_stdout(output):
                handle_jobs(jobs_root=jobs_root, use_color=False)
                handle_enter("#A12F", state, jobs_root=jobs_root, use_color=False)
                handle_show(state, jobs_root=jobs_root, use_color=False)
                handle_leave_job(state, use_color=False)

        text = output.getvalue()
        self.assertIn("#A12F  recon     initialized", text)
        self.assertIn("[info] entered job #A12F", text)
        self.assertIn("[job]", text)
        self.assertIn("steps    : 0", text)
        self.assertIn("results  : 0", text)
        self.assertIn("[info] left job #A12F", text)
        self.assertEqual(state.active_job, "")

    def test_show_specific_job_by_id(self):
        state = ShellState()
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            with redirect_stdout(io.StringIO()):
                handle_new(
                    "recon[target=192.168.1.1]",
                    state,
                    jobs_root=jobs_root,
                    created_at=datetime(2026, 4, 23, 10, 32),
                    job_id="A12F",
                    use_color=False,
                )
            state.active_job = ""

            with redirect_stdout(output):
                handle_show(state, "#A12F", jobs_root=jobs_root, use_color=False)

        text = output.getvalue()
        self.assertIn("[job]", text)
        self.assertIn("id       : #A12F", text)
        self.assertIn("type     : ip", text)
        self.assertIn("results  : 0", text)

    def test_append_job_result_upgrades_job_status_and_summary(self):
        state = ShellState()

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            with redirect_stdout(io.StringIO()):
                handle_new(
                    "recon[target=10.0.0.1,strategy=balanced]",
                    state,
                    jobs_root=jobs_root,
                    created_at=datetime(2026, 4, 23, 10, 32),
                    job_id="A12F",
                    use_color=False,
                )

            append_job_result(
                "A12F",
                {
                    "recorded_at": "2026-04-23T10:33:00",
                    "module": "recon",
                    "tool": "nmap",
                    "action": "scan",
                    "ok": True,
                    "error": "",
                    "summary": {
                        "target": "10.0.0.1",
                        "host_status": "up",
                        "open_ports": 2,
                        "elapsed_seconds": 49.96,
                    },
                    "payload": {
                        "command": ["nmap", "-Pn", "-T3", "-p", "1-1024", "10.0.0.1"],
                        "target": "10.0.0.1",
                        "host_status": "up",
                        "raw_output": "PORT    STATE SERVICE\n80/tcp open http\n443/tcp open https\n",
                        "ports": [
                            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                            {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
                        ],
                        "warnings": [],
                        "elapsed_seconds": 49.96,
                    },
                },
                jobs_root=jobs_root,
            )

            job = load_job("A12F", jobs_root)

        self.assertIsNotNone(job)
        assert job is not None
        self.assertEqual(job.status, "completed")
        self.assertEqual(job.summary["step_count"], 1)
        self.assertEqual(job.summary["result_count"], 1)
        self.assertEqual(job.summary["open_ports"], 2)
        self.assertEqual(job.summary["host_status"], "up")
        self.assertEqual(len(job.steps), 1)
        self.assertEqual(job.steps[0]["name"], "port_scan")
        self.assertEqual(job.steps[0]["status"], "completed")
        self.assertEqual(job.steps[0]["provenance"]["tool"], "nmap")

    def test_append_job_result_marks_http_mixed_findings_as_completed_with_warnings(self):
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

            append_job_result(
                "A12F",
                {
                    "recorded_at": "2026-04-23T10:33:00",
                    "module": "recon",
                    "tool": "http",
                    "action": "http_ip_probe",
                    "ok": True,
                    "error": "",
                    "summary": {
                        "target": "10.0.0.1",
                        "mode": "http_ip_probe",
                        "findings": 2,
                        "elapsed_seconds": 0.4,
                    },
                    "payload": {
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
                },
                jobs_root=jobs_root,
            )

            job = load_job("A12F", jobs_root)

        self.assertIsNotNone(job)
        assert job is not None
        self.assertEqual(job.status, "completed_with_warnings")
        self.assertEqual(job.steps[0]["status"], "completed_with_warnings")
        self.assertEqual(job.summary["warning_steps"], 1)
        self.assertEqual(job.summary["elapsed_seconds"], 0.4)

    def test_append_job_result_marks_mixed_failed_and_completed_steps_as_partial(self):
        state = ShellState()

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            with redirect_stdout(io.StringIO()):
                handle_new(
                    "recon[target=example.com]",
                    state,
                    jobs_root=jobs_root,
                    created_at=datetime(2026, 4, 23, 10, 32),
                    job_id="A12F",
                    use_color=False,
                )

            append_job_result(
                "A12F",
                {
                    "recorded_at": "2026-04-23T10:33:00",
                    "module": "recon",
                    "tool": "dns",
                    "action": "dns",
                    "ok": False,
                    "error": "dns lookup failed for example.com",
                    "summary": {
                        "target": "example.com",
                        "record_count": 0,
                        "elapsed_seconds": 0.1,
                    },
                    "payload": {
                        "target": "example.com",
                        "host": "example.com",
                        "records": {"A": [], "AAAA": [], "MX": [], "NS": []},
                        "resolved_ips": [],
                        "provider": "custom",
                        "raw_output": "",
                        "elapsed_seconds": 0.1,
                    },
                },
                jobs_root=jobs_root,
            )
            append_job_result(
                "A12F",
                {
                    "recorded_at": "2026-04-23T10:34:00",
                    "module": "recon",
                    "tool": "nmap",
                    "action": "port_scan",
                    "ok": True,
                    "error": "",
                    "summary": {
                        "target": "example.com",
                        "host_status": "up",
                        "open_ports": 2,
                        "elapsed_seconds": 12.4,
                    },
                    "payload": {
                        "command": ["nmap", "-Pn", "-T3", "-p", "1-1024", "example.com"],
                        "target": "example.com",
                        "host_status": "up",
                        "raw_output": "",
                        "ports": [
                            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                            {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
                        ],
                        "warnings": [],
                        "elapsed_seconds": 12.4,
                    },
                },
                jobs_root=jobs_root,
            )

            job = load_job("A12F", jobs_root)

        self.assertIsNotNone(job)
        assert job is not None
        self.assertEqual(job.status, "partial")
        self.assertEqual(job.summary["failed_steps"], 1)
        self.assertEqual(job.summary["completed_steps"], 1)
        self.assertEqual(job.summary["elapsed_seconds"], 12.5)

    def test_load_job_preserves_legacy_shape_without_corruption(self):
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            (jobs_root / "A12F.json").write_text(
                json.dumps(
                    {
                        "id": "A12F",
                        "module": "recon",
                        "params": {"target": "10.0.0.1"},
                        "created": "2026-04-23 10:32",
                        "status": "initialized",
                        "results": [
                            {
                                "recorded_at": "2026-04-23T10:33:00",
                                "module": "recon",
                                "tool": "nmap",
                                "action": "scan",
                                "ok": True,
                                "error": "",
                                "summary": {
                                    "target": "10.0.0.1",
                                    "host_status": "up",
                                    "open_ports": 3,
                                    "elapsed_seconds": 49.96,
                                },
                                "payload": {
                                    "command": ["nmap", "-Pn", "-T3", "-p", "1-1024", "10.0.0.1"],
                                    "target": "10.0.0.1",
                                    "host_status": "up",
                                    "raw_output": "",
                                    "ports": [
                                        {"port": 53, "protocol": "tcp", "state": "open", "service": "domain"},
                                        {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                                        {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
                                    ],
                                    "warnings": [],
                                    "elapsed_seconds": 49.96,
                                },
                            }
                        ],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            job = load_job("A12F", jobs_root)
            with redirect_stdout(output):
                handle_show(ShellState(), "#A12F", jobs_root=jobs_root, use_color=False)

        self.assertIsNotNone(job)
        assert job is not None
        self.assertEqual(job.target, "10.0.0.1")
        self.assertEqual(job.target_type, "ip")
        self.assertEqual(job.status, "completed")
        self.assertEqual(len(job.steps), 1)
        self.assertEqual(job.summary["open_ports"], 3)
        text = output.getvalue()
        self.assertIn("status   : completed", text)
        self.assertIn("steps    : 1", text)
        self.assertIn("results  : 1", text)
        self.assertIn("open     : 3", text)

    def test_delete_job_removes_file_and_clears_active_context(self):
        state = ShellState(active_job="A12F")
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            with redirect_stdout(io.StringIO()):
                handle_new(
                    "recon[target=192.168.1.1]",
                    state,
                    jobs_root=jobs_root,
                    created_at=datetime(2026, 4, 23, 10, 32),
                    job_id="A12F",
                    use_color=False,
                )

            with redirect_stdout(output):
                deleted = handle_delete_job("#A12F", state, jobs_root=jobs_root, use_color=False)

            exists = (jobs_root / "A12F.json").exists()

        self.assertTrue(deleted)
        self.assertFalse(exists)
        self.assertEqual(state.active_job, "")
        self.assertEqual(output.getvalue().splitlines(), ["[info] left job #A12F", "[result] job deleted: #A12F"])

    def test_delete_multiple_jobs(self):
        state = ShellState(active_job="B93K")
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            for identifier in ("A12F", "B93K"):
                with redirect_stdout(io.StringIO()):
                    handle_new(
                        "",
                        state,
                        jobs_root=jobs_root,
                        created_at=datetime(2026, 4, 23, 10, 32),
                        job_id=identifier,
                        use_color=False,
                    )
            state.active_job = "B93K"

            with redirect_stdout(output):
                deleted = handle_delete_job("#A12F, #B93K", state, jobs_root=jobs_root, use_color=False)

            remaining = list_job_ids(jobs_root)

        self.assertTrue(deleted)
        self.assertEqual(remaining, [])
        self.assertEqual(state.active_job, "")
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "[info] left job #B93K",
                "[result] job deleted: #A12F",
                "[result] job deleted: #B93K",
            ],
        )

    def test_delete_all_jobs_with_star(self):
        state = ShellState(active_job="A12F")

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            for identifier in ("A12F", "B93K"):
                with redirect_stdout(io.StringIO()):
                    handle_new(
                        "",
                        state,
                        jobs_root=jobs_root,
                        created_at=datetime(2026, 4, 23, 10, 32),
                        job_id=identifier,
                        use_color=False,
                    )
            state.active_job = "A12F"

            with redirect_stdout(io.StringIO()):
                deleted = handle_delete_job("*", state, jobs_root=jobs_root, use_color=False)

            remaining = list_job_ids(jobs_root)

        self.assertTrue(deleted)
        self.assertEqual(remaining, [])
        self.assertEqual(state.active_job, "")

    def test_parse_delete_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            for identifier in ("A12F", "B93K"):
                with redirect_stdout(io.StringIO()):
                    handle_new("", ShellState(), jobs_root=jobs_root, job_id=identifier, use_color=False)

            self.assertEqual(parse_delete_targets("#A12F, B93K", jobs_root), ["A12F", "B93K"])
            self.assertEqual(parse_delete_targets("*", jobs_root), ["A12F", "B93K"])

    def test_delete_job_reports_missing_job(self):
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp:
            with redirect_stdout(output):
                deleted = handle_delete_job("NOPE", ShellState(), jobs_root=Path(tmp), use_color=False)

        self.assertFalse(deleted)
        self.assertEqual(output.getvalue().strip(), "[error] job not found: #NOPE")

    def test_dispatch_exit_leaves_active_job_before_shell_exit(self):
        state = ShellState(active_job="A12F")
        output = io.StringIO()

        with redirect_stdout(output):
            should_exit = dispatch_line("exit", state)

        self.assertFalse(should_exit)
        self.assertEqual(state.active_job, "")
        self.assertEqual(output.getvalue().strip(), "[info] left job #A12F")


if __name__ == "__main__":
    unittest.main()
