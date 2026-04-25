import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

from blackline.cli.commands.system.jobs_cmd import (
    handle_delete_job,
    handle_enter,
    handle_jobs,
    handle_leave_job,
    handle_new,
    handle_show,
    list_job_ids,
    parse_delete_targets,
    parse_job_expression,
)
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.cli.core_shell import dispatch_line


class JobsCommandTests(unittest.TestCase):
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
        text = output.getvalue()
        self.assertIn("[job]", text)
        self.assertIn("id      : #A12F", text)
        self.assertIn("module  : recon", text)
        self.assertIn("target  : 192.168.1.1", text)
        self.assertIn("created : 2026-04-23 10:32", text)
        self.assertIn("status  : initialized", text)
        self.assertIn("results : 0", text)
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
        self.assertIn("id      : #B93K", text)
        self.assertIn("module  : manual", text)
        self.assertIn("results : 0", text)
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
        self.assertIn("results : 0", text)
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
        self.assertIn("id      : #A12F", text)
        self.assertIn("results : 0", text)

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
