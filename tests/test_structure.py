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
            "cli/commands/recon",
            "cli/commands/network",
            "cli/commands/utils",
            "cli/parser/intent_parser.py",
            "cli/parser/tokenizer.py",
            "engine/context.py",
            "engine/runner.py",
            "engine/planner.py",
            "engine/executor.py",
            "engine/pipeline.py",
            "engine/session.py",
            "tools/network/nmap.py",
            "tools/http/curl_probe.py",
            "tools/parsers/nmap.py",
            "tools/parsers/curl.py",
            "operators/background.py",
            "operators/parallel.py",
            "operators/sequence.py",
            "operators/conditional.py",
            "config/commands.json",
            "config/operators.json",
            "config/tools.json",
            "config/defaults.json",
            "config/global.json",
            "storage/database",
            "storage/cache",
            "utils/exec.py",
            "utils/string_matcher.py",
            "utils/tab_complete.py",
        ]

        for path in expected:
            with self.subTest(path=path):
                self.assertTrue((root / path).exists())


if __name__ == "__main__":
    unittest.main()
