import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from blackline.cli.commands.utils.shell_cmds import (
    ShellState,
    handle_clear,
    handle_history,
    handle_history_clear,
    handle_reset,
    handle_version,
)
from blackline.cli.core_shell import dispatch_line, execute_shell_line


class ShellCommandTests(unittest.TestCase):
    def test_clear_outputs_terminal_clear_sequence(self):
        output = io.StringIO()

        with redirect_stdout(output):
            handle_clear()

        self.assertEqual(output.getvalue(), "\033[2J\033[H")

    def test_version_outputs_short_version(self):
        output = io.StringIO()

        with redirect_stdout(output):
            handle_version(use_color=False)

        self.assertEqual(output.getvalue().strip(), "[result] blackline v0.1")

    def test_history_outputs_session_commands(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            state = ShellState(history_path=Path(tmp) / "commands.jsonl")
            with redirect_stdout(io.StringIO()):
                dispatch_line("network", state)
                dispatch_line("version", state)

            with redirect_stdout(output):
                handle_history(state, use_color=False)

        self.assertEqual(output.getvalue().splitlines(), ["1  network", "2  version"])

    def test_history_empty_message(self):
        output = io.StringIO()

        with redirect_stdout(output):
            handle_history(ShellState(history_path=Path("/tmp/blackline-no-history.jsonl")), use_color=False)

        self.assertEqual(output.getvalue().strip(), "[info] history is empty")

    def test_reset_clears_history(self):
        state = ShellState(history=["network"])
        output = io.StringIO()

        with redirect_stdout(output):
            handle_reset(state, use_color=False)

        self.assertEqual(state.history, [])
        self.assertEqual(output.getvalue().strip(), "[result] session state reset")

    def test_dispatch_wires_common_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = ShellState(history_path=Path(tmp) / "commands.jsonl")
            output = io.StringIO()

            with redirect_stdout(output):
                should_exit = dispatch_line("version", state)
                dispatch_line("history", state)

            self.assertFalse(should_exit)
            text = output.getvalue()
            self.assertIn("[result] blackline v0.1", text)
            self.assertIn("1  version", text)
            self.assertIn("2  history", text)

    def test_dispatch_placeholder_for_planned_commands(self):
        output = io.StringIO()

        with redirect_stdout(output):
            dispatch_line("run recon", ShellState())

        self.assertEqual(output.getvalue().strip(), "[warn] run is planned but not wired to the engine yet")

    def test_execute_shell_line_adds_spacing_around_command_output(self):
        output = io.StringIO()

        with redirect_stdout(output):
            execute_shell_line("version", ShellState())

        self.assertEqual(output.getvalue(), "\n[result] blackline v0.1\n\n")

    def test_execute_shell_line_keeps_empty_input_tight(self):
        output = io.StringIO()

        with redirect_stdout(output):
            should_exit = execute_shell_line("", ShellState())

        self.assertFalse(should_exit)
        self.assertEqual(output.getvalue(), "")

    def test_history_filters_clear_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = ShellState(history_path=Path(tmp) / "commands.jsonl")
            with redirect_stdout(io.StringIO()):
                dispatch_line("network", state)
                dispatch_line("clear", state)
                dispatch_line("version", state)
            output = io.StringIO()

            with redirect_stdout(output):
                handle_history(state, use_color=False)

        self.assertEqual(output.getvalue().splitlines(), ["1  network", "2  version"])

    def test_history_all_shows_filtered_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = ShellState(history_path=Path(tmp) / "commands.jsonl")
            with redirect_stdout(io.StringIO()):
                dispatch_line("network", state)
                dispatch_line("clear", state)
                dispatch_line("version", state)
            output = io.StringIO()

            with redirect_stdout(output):
                handle_history(state, show_all=True, use_color=False)

        self.assertEqual(output.getvalue().splitlines(), ["1  network", "2  clear", "3  version"])

    def test_history_clear_removes_stored_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            history_path = Path(tmp) / "commands.jsonl"
            state = ShellState(history_path=history_path)
            with redirect_stdout(io.StringIO()):
                dispatch_line("network", state)
                dispatch_line("version", state)

            output = io.StringIO()
            with redirect_stdout(output):
                handle_history_clear(state, use_color=False)

            self.assertEqual(state.history, [])
            self.assertFalse(history_path.exists())
            self.assertEqual(output.getvalue().strip(), "[result] history cleared")


if __name__ == "__main__":
    unittest.main()
