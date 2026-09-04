import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
import io

from blackline.cli.commands.system.jobs_cmd import handle_new
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.utils import tab_complete
from blackline.utils.tab_complete import (
    command_spans,
    completion_items,
    complete_text,
    current_completion_length,
    delete_target_replacements,
    enter_target_replacements,
    next_suggestions,
    show_target_replacements,
)


class TabCompleteTests(unittest.TestCase):
    def test_command_completion_loads_from_config(self):
        self.assertIn("network ", complete_text("net"))
        self.assertIn("help ", complete_text("he"))

    def test_help_completion_loads_topics_from_config(self):
        suggestions = complete_text("help rec")

        self.assertIn("recon ", suggestions)

    def test_category_completion_loads_topics_from_config(self):
        suggestions = complete_text("help oper")

        self.assertEqual(suggestions, ["operators "])

    def test_operator_completion_loads_from_config(self):
        self.assertIn("// ", complete_text("run recon /"))

    def test_command_completion_after_operator_loads_from_config(self):
        self.assertIn("network ", complete_text("help // "))

    def test_next_suggestions_are_display_friendly(self):
        self.assertIn("network", next_suggestions("net"))

    def test_command_spans_validate_multiple_commands(self):
        spans = command_spans("help recon // nope[target=1.1.1.1] & network")

        self.assertEqual(
            spans,
            [
                (0, 4, True),
                (14, 18, False),
                (37, 44, True),
            ],
        )

    def test_delete_completion_lists_existing_jobs_and_star(self):
        original_default_jobs_root = tab_complete.list_jobs.__globals__["default_jobs_root"]

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            for identifier in ("A12F", "B93K"):
                with redirect_stdout(io.StringIO()):
                    handle_new("", ShellState(), jobs_root=jobs_root, job_id=identifier, use_color=False)

            def fake_default_jobs_root():
                return jobs_root

            tab_complete.list_jobs.__globals__["default_jobs_root"] = fake_default_jobs_root
            try:
                self.assertEqual(delete_target_replacements("delete "), ["*", "#A12F", "#B93K"])
                self.assertEqual(delete_target_replacements("delete #A"), ["#A12F"])
                self.assertEqual(delete_target_replacements("delete #A12F, #"), ["#B93K"])
                self.assertIn(("#A12F", "manual initialized"), completion_items("delete #A"))
                self.assertIn(("*", "all jobs"), completion_items("delete "))
            finally:
                tab_complete.list_jobs.__globals__["default_jobs_root"] = original_default_jobs_root

    def test_delete_completion_replacement_length_after_comma(self):
        self.assertEqual(current_completion_length("delete #A12F, #B", "#B"), 2)

    def test_enter_completion_lists_existing_jobs(self):
        original_default_jobs_root = tab_complete.list_jobs.__globals__["default_jobs_root"]

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            for identifier in ("A12F", "B93K"):
                with redirect_stdout(io.StringIO()):
                    handle_new("", ShellState(), jobs_root=jobs_root, job_id=identifier, use_color=False)

            def fake_default_jobs_root():
                return jobs_root

            tab_complete.list_jobs.__globals__["default_jobs_root"] = fake_default_jobs_root
            try:
                self.assertEqual(enter_target_replacements("enter "), ["#A12F", "#B93K"])
                self.assertEqual(enter_target_replacements("enter #B"), ["#B93K"])
                self.assertIn(("#A12F", "manual initialized"), completion_items("enter #A"))
            finally:
                tab_complete.list_jobs.__globals__["default_jobs_root"] = original_default_jobs_root

    def test_enter_completion_replacement_length(self):
        self.assertEqual(current_completion_length("enter #A", "#A"), 2)

    def test_show_completion_lists_existing_jobs(self):
        original_default_jobs_root = tab_complete.list_jobs.__globals__["default_jobs_root"]

        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            for identifier in ("A12F", "B93K"):
                with redirect_stdout(io.StringIO()):
                    handle_new("", ShellState(), jobs_root=jobs_root, job_id=identifier, use_color=False)

            def fake_default_jobs_root():
                return jobs_root

            tab_complete.list_jobs.__globals__["default_jobs_root"] = fake_default_jobs_root
            try:
                self.assertEqual(show_target_replacements("show "), [
                    "formatted", "sources", "raw", "dns", "network", "web", "fingerprint", "tls", "rdap", "services", "system", "correlation", "#A12F", "#B93K",
                ])
                self.assertEqual(show_target_replacements("show #B"), ["#B93K"])
                self.assertIn(("#A12F", "manual initialized"), completion_items("show #A"))
                self.assertIn(("sources", "job provenance"), completion_items("show so"))
            finally:
                tab_complete.list_jobs.__globals__["default_jobs_root"] = original_default_jobs_root

    def test_show_completion_replacement_length(self):
        self.assertEqual(current_completion_length("show #A", "#A"), 2)

    def test_recon_key_completion_inside_brackets(self):
        items = completion_items("recon[pro")

        self.assertIn(("probe=", "how deep to fingerprint services"), items)

    def test_recon_value_completion_inside_brackets(self):
        items = completion_items("recon[strategy=qu")

        self.assertIn(("quiet, ", "recon profile or scan strategy"), items)
        self.assertIn(("surface, ", "recon profile or scan strategy"), completion_items("recon[strategy=su"))

    def test_recon_probe_value_completion_inside_brackets(self):
        items = completion_items("recon[probe=fi")

        self.assertIn(("fingerprint, ", "how deep to fingerprint services"), items)

    def test_recon_value_completion_length_inside_brackets(self):
        self.assertEqual(current_completion_length("recon[strategy=qu", "strategy=qu"), 2)

    def test_command_completion_degrades_when_help_config_loader_fails(self):
        original_load_help_groups = tab_complete.load_help_groups

        def broken_load_help_groups():
            raise FileNotFoundError("commands.json is missing")

        tab_complete.load_help_groups = broken_load_help_groups
        try:
            self.assertEqual(complete_text("he"), [])
            self.assertEqual(command_spans("help nope"), [(0, 4, False)])
        finally:
            tab_complete.load_help_groups = original_load_help_groups


if __name__ == "__main__":
    unittest.main()
