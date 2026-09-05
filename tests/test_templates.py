"""End-to-end lifecycle tests for reusable `.bline` templates."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from blackline.clt.errors import CLTError
from blackline.clt import compile_source
from blackline.cli.commands.templates.template_cmd import handle_edit, handle_list_templates, handle_load, handle_run, handle_use
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.templates import DuplicateTemplateError, TemplateRegistry, TemplateStatus, TemplateStorage


class TemplateRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.registry = TemplateRegistry(storage=TemplateStorage(self.root / "registry.json"))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_template(self, name: str, source: str = "analyze\n") -> Path:
        path = self.root / f"{name}.bline"
        path.write_text(source, encoding="utf-8")
        return path

    def test_register_compiles_and_persists_a_template_reference(self):
        path = self.write_template("hello")
        loaded = self.registry.register(path)
        reopened = TemplateRegistry(storage=TemplateStorage(self.root / "registry.json"))

        self.assertEqual((loaded.name, loaded.status), ("hello", TemplateStatus.LOADED))
        self.assertEqual(reopened.get("hello").path, path.resolve())
        self.assertIsNotNone(reopened.executable("hello").compiled)

    def test_register_accepts_an_omitted_bline_extension(self):
        path = self.write_template("hello")

        loaded = self.registry.register(path.with_suffix(""))

        self.assertEqual(loaded.path, path.resolve())

    def test_invalid_source_does_not_create_a_registration(self):
        path = self.write_template("broken", "if port open\n    -> inspect ssh\n")

        with self.assertRaises(CLTError):
            self.registry.register(path)

        self.assertEqual(self.registry.list(), ())

    def test_duplicate_name_from_another_source_is_rejected(self):
        first = self.write_template("web-audit")
        self.registry.register(first)
        other_root = self.root / "other"
        other_root.mkdir()
        second = other_root / "web-audit.bline"
        second.write_text("analyze\n", encoding="utf-8")

        with self.assertRaises(DuplicateTemplateError):
            self.registry.register(second)

    def test_invalid_edit_preserves_the_last_valid_compilation(self):
        path = self.write_template("hello")
        first = self.registry.register(path)
        path.write_text("if port open\n    -> inspect ssh\n", encoding="utf-8")
        refreshed = self.registry.refresh("hello")

        self.assertEqual(refreshed.status, TemplateStatus.INVALID)
        self.assertEqual(refreshed.compiled, first.compiled)
        self.assertIsNotNone(self.registry.executable("hello").compiled)

    def test_missing_source_remains_registered_with_missing_status(self):
        path = self.write_template("hello")
        self.registry.register(path)
        path.unlink()

        self.assertEqual(self.registry.list()[0].status, TemplateStatus.MISSING)

    def test_checked_in_template_fixtures_compile(self):
        fixtures = Path(__file__).with_name("templates")
        for path in sorted(fixtures.glob("*.bline")):
            with self.subTest(template=path.name):
                compile_source(path.read_text(encoding="utf-8"), filename=str(path))


class TemplateCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.registry = TemplateRegistry(storage=TemplateStorage(self.root / "registry.json"))
        self.state = ShellState(template_registry=self.registry)
        self.path = self.root / "hello.bline"
        self.path.write_text("analyze\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_load_use_list_and_run_follow_the_template_lifecycle(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertTrue(handle_load(str(self.path), self.state, use_color=False))
            self.assertTrue(handle_use("hello", self.state, use_color=False))
            self.assertTrue(handle_list_templates(self.state, use_color=False))
            self.assertTrue(handle_run("", self.state, use_color=False))

        text = output.getvalue()
        self.assertIn("[load] hello", text)
        self.assertIn("[use] hello", text)
        self.assertIn("hello  active", text)
        self.assertIn("[run] hello completed", text)
        self.assertIn("analyze  done", text)

    def test_bare_load_explains_the_path_syntax(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertFalse(handle_load("", self.state, use_color=False))

        self.assertIn("example: load ./web-audit.bline", output.getvalue())

    def test_edit_revalidates_the_user_owned_source_after_editor_exit(self):
        self.registry.register(self.path)

        def modify_source(_: list[str]) -> None:
            self.path.write_text("report\n", encoding="utf-8")

        output = io.StringIO()
        with redirect_stdout(output):
            self.assertTrue(handle_edit("hello", self.state, editor="fake-editor", editor_runner=modify_source, use_color=False))

        self.assertIn("[result] hello updated", output.getvalue())
        self.assertEqual(self.registry.get("hello").status, TemplateStatus.LOADED)

    def test_editing_to_invalid_source_keeps_the_last_valid_template(self):
        self.registry.register(self.path)

        def break_source(_: list[str]) -> None:
            self.path.write_text("if port open\n    -> inspect ssh\n", encoding="utf-8")

        with redirect_stdout(io.StringIO()):
            self.assertFalse(handle_edit("hello", self.state, editor="fake-editor", editor_runner=break_source, use_color=False))
        self.assertEqual(self.registry.get("hello").status, TemplateStatus.INVALID)
        with redirect_stdout(io.StringIO()):
            self.assertTrue(handle_run("hello", self.state, use_color=False))


if __name__ == "__main__":
    unittest.main()
