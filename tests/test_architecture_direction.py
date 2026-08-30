import unittest
from pathlib import Path


class ArchitectureDirectionTests(unittest.TestCase):
    def test_refined_architecture_scaffold_exists(self):
        root = Path(__file__).resolve().parents[1] / "blackline"
        expected = [
            "core/recon/models.py",
            "core/recon/pipeline.py",
            "core/recon/steps",
            "engine/context.py",
            "storage/cache",
            "cli/commands/recon/recon_cmd.py",
            "cli/commands/network/network_cmd.py",
            "tools/network/nmap.py",
            "tools/parsers/nmap.py",
            "tools/intel/yougotmapped.py",
        ]

        for path in expected:
            with self.subTest(path=path):
                self.assertTrue((root / path).exists())

    def test_deprecated_duplicate_python_layers_are_gone(self):
        root = Path(__file__).resolve().parents[1] / "blackline"
        deprecated = [
            "cli/commands/tools",
            "engine/state",
            "tools/recon",
            "tools/probes",
            "modules",
        ]

        for path in deprecated:
            with self.subTest(path=path):
                self.assertFalse((root / path).exists())


if __name__ == "__main__":
    unittest.main()
