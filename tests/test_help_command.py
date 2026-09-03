import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from blackline.cli.commands.system.help_cmd import (
    handle_help,
    load_help_groups,
    render_main_help,
)


class HelpCommandTests(unittest.TestCase):
    def test_main_help_renders_configured_sections(self):
        output = io.StringIO()

        with redirect_stdout(output):
            handle_help(use_color=False)

        text = output.getvalue()
        self.assertIn("blackline v0.1", text)
        self.assertIn("UTILS\n─────", text)
        self.assertIn("TOOLS\n─────", text)
        self.assertIn("OPERATORS\n─────────", text)
        self.assertIn("run        execute current module or command", text)
        self.assertIn("network    show local and external network identity", text)
        self.assertIn("recon         target discovery (ip, url, email, etc.)", text)
        self.assertIn("&   and-sequence", text)
        self.assertIn("//  parallel", text)
        self.assertIn("type 'help <command>' for details", text)

    def test_command_help_renders_details(self):
        output = io.StringIO()

        with redirect_stdout(output):
            handle_help("recon", use_color=False)

        text = output.getvalue()
        self.assertIn("[recon]", text)
        self.assertIn("description\n───────────", text)
        self.assertIn("perform reconnaissance on a target", text)
        self.assertIn("usage\n─────", text)
        self.assertIn("recon[target=<ip>,strategy=<mode>,probe=<depth>]", text)
        self.assertIn("arguments\n─────────", text)
        self.assertIn("target    target ip or domain", text)
        self.assertIn("strategy  surface, balanced, quiet, fast, deep, or udp", text)
        self.assertIn("examples\n────────", text)
        self.assertIn("recon[target=example.com,strategy=quiet,top_ports=20]", text)

    def test_category_help_renders_only_category(self):
        output = io.StringIO()

        with redirect_stdout(output):
            handle_help("tools", use_color=False)

        text = output.getvalue()
        self.assertIn("TOOLS\n─────", text)
        self.assertIn("recon", text)
        self.assertNotIn("UTILS", text)

    def test_operators_help_renders_operators_only(self):
        output = io.StringIO()

        with redirect_stdout(output):
            handle_help("operators", use_color=False)

        text = output.getvalue()
        self.assertIn("OPERATORS\n─────────", text)
        self.assertIn("//  parallel", text)
        self.assertIn("stdout → stdin", text)
        self.assertNotIn("UTILS", text)

    def test_help_loads_from_config_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "commands.json").write_text(
                """
                {
                  "groups": [
                    {
                      "id": "custom",
                      "title": "CUSTOM",
                      "items": [
                        {
                          "name": "pulse",
                          "description": "check heartbeat",
                          "usage": "pulse",
                          "arguments": [],
                          "examples": ["pulse"]
                        }
                      ]
                    }
                  ]
                }
                """,
                encoding="utf-8",
            )

            groups = load_help_groups(root)
            output = io.StringIO()

            with redirect_stdout(output):
                render_main_help(groups, (), width=40, use_color=False)

        self.assertIn("pulse      check heartbeat", output.getvalue())

    def test_main_help_rule_expands_to_width(self):
        groups = load_help_groups()
        output = io.StringIO()

        with redirect_stdout(output):
            render_main_help(groups, (), width=52, use_color=False)

        lines = output.getvalue().splitlines()
        self.assertEqual(lines[1], "─" * 52)

    def test_missing_help_config_returns_empty_groups(self):
        with tempfile.TemporaryDirectory() as tmp:
            groups = load_help_groups(Path(tmp))

        self.assertEqual(groups, ())


if __name__ == "__main__":
    unittest.main()
