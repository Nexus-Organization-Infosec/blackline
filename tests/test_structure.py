import unittest
from pathlib import Path


class StructureTests(unittest.TestCase):
    def test_requested_structure_exists(self):
        root = Path(__file__).resolve().parents[1] / "blackline"
        expected = [
            "cli/cli.py",
            "cli/core_shell.py",
            "cli/ui/elements.py",
            "cli/ui/colors.py",
            "cli/ui/display.py",
            "cli/commands/system",
            "cli/commands/utils",
            "cli/commands/tools",
            "cli/parser/intent_parser.py",
            "cli/parser/tokenizer.py",
            "engine/runner.py",
            "engine/planner.py",
            "engine/executor.py",
            "engine/pipeline.py",
            "engine/state/session.py",
            "engine/state/context.py",
            "tools/recon/nmap.py",
            "tools/recon/curl_probe.py",
            "tools/recon/parsers/nmap_parser.py",
            "tools/recon/parsers/curl_probe_parser.py",
            "operators/background.py",
            "operators/parallel.py",
            "operators/sequence.py",
            "operators/conditional.py",
            "modules",
            "config/commands.json",
            "config/operators.json",
            "config/tools.json",
            "config/defaults.json",
            "config/global.json",
            "storage/history",
            "storage/database",
            "utils/exec.py",
            "utils/string_matcher.py",
            "utils/tab_complete.py",
        ]

        for path in expected:
            with self.subTest(path=path):
                self.assertTrue((root / path).exists())


if __name__ == "__main__":
    unittest.main()

