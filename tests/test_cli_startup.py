import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from blackline.cli.ui.elements import render_startup, run_startup_checks


class StartupUITests(unittest.TestCase):
    def test_render_startup_matches_expected_shape(self):
        results = run_startup_checks()
        output = io.StringIO()

        with redirect_stdout(output):
            render_startup(results, use_color=False)

        text = output.getvalue()
        self.assertIn("[ blackline ]", text)
        self.assertIn("version: v0.1", text)
        self.assertIn("initializing...", text)
        self.assertIn("loading modules .......... ok", text)
        self.assertIn("loading operators ........ ok", text)
        self.assertIn("loading tools ............ ok", text)
        self.assertIn("loading config ........... ok", text)
        self.assertIn("initializing engine ...... ok", text)
        self.assertTrue(text.rstrip().endswith("ready."))

    def test_startup_checks_report_missing_required_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "modules").mkdir()
            results = run_startup_checks(root)

        failed = [result for result in results if not result.ok]
        self.assertTrue(failed)
        self.assertIn("operators", failed[0].detail)


if __name__ == "__main__":
    unittest.main()
