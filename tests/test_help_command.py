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
        self.assertIn("run        execute an active or named template", text)
        self.assertIn("load       register and validate a .bline template", text)
        self.assertIn("network    show local and external network identity", text)
        self.assertIn("recon         build an evidence-backed target profile", text)
        self.assertIn("&   and-sequence", text)
        self.assertIn("//  parallel", text)
        self.assertNotIn("SYSTEMS", text)
        self.assertNotIn("clt", text.lower())
        self.assertIn("type 'help <command>' for details", text)

    def test_command_help_renders_details(self):
        output = io.StringIO()

        with redirect_stdout(output):
            handle_help("recon", use_color=False)

        text = output.getvalue()
        self.assertIn("[recon]", text)
        self.assertIn("description\n───────────", text)
        self.assertIn("collect DNS, web, TLS, registration, network, and service evidence", text)
        self.assertIn("usage\n─────", text)
        self.assertIn("recon[target=<ip|domain|url>, strategy=<profile>, ...]", text)
        self.assertIn("arguments\n─────────", text)
        self.assertIn("target     required IP address, domain, or URL", text)
        self.assertIn("strategy   scanning profile", text)
        self.assertIn("├─ surface   quick exposed-service discovery", text)
        self.assertIn("├─ balanced  general-purpose service discovery (default)", text)
        self.assertIn("└─ udp       UDP-focused service discovery", text)
        self.assertIn("ports      custom Nmap port expression", text)
        self.assertIn("transport  transport override: tcp or udp", text)
        self.assertIn("examples\n────────", text)
        self.assertIn("recon[target=10.0.0.236,strategy=deep,speed=high,probe=fingerprint]", text)

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
