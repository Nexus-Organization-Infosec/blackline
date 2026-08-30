import io
import unittest
from contextlib import redirect_stdout

from blackline.cli.ui.display import error, info, job_id, result, section, warn
from blackline.cli.ui.elements import prompt_line
from blackline.cli.ui.live_input import prompt_fragments


class CLIUITests(unittest.TestCase):
    def test_prompt_line(self):
        self.assertEqual(prompt_line(), "blackline ❯ ")

    def test_elevated_prompt_line(self):
        self.assertEqual(prompt_line(elevated=True), "blackline # ")

    def test_job_prompt_line(self):
        self.assertEqual(prompt_line("A12F"), "bl [#A12F] ❯ ")

    def test_elevated_job_prompt_line(self):
        self.assertEqual(prompt_line("A12F", elevated=True), "bl [#A12F] # ")

    def test_prompt_line_color(self):
        self.assertEqual(
            prompt_line(use_color=True),
            "\001\033[38;5;82m\002blackline\001\033[0m\002"
            "\001\033[38;5;214m\002 ❯ \001\033[0m\002",
        )

    def test_job_prompt_line_color(self):
        self.assertEqual(
            prompt_line("A12F", use_color=True),
            "\001\033[38;5;82m\002bl\001\033[0m\002"
            "\001\033[38;5;252m\002 [\001\033[0m\002"
            "\001\033[38;5;51m\002#A12F\001\033[0m\002"
            "\001\033[38;5;214m\002] ❯ \001\033[0m\002",
        )

    def test_prompt_toolkit_prompt_fragments(self):
        self.assertEqual(
            prompt_fragments(),
            [
                ("class:prompt.name", "blackline"),
                ("class:prompt.arrow", " ❯ "),
            ],
        )

    def test_prompt_toolkit_elevated_prompt_fragments(self):
        self.assertEqual(
            prompt_fragments(elevated=True),
            [
                ("class:prompt.name", "blackline"),
                ("class:prompt.arrow", " # "),
            ],
        )

    def test_prompt_toolkit_job_prompt_fragments(self):
        self.assertEqual(
            prompt_fragments("A12F"),
            [
                ("class:prompt.name", "bl"),
                ("class:prompt.bracket", " ["),
                ("class:prompt.job", "#A12F"),
                ("class:prompt.arrow", "] ❯ "),
            ],
        )

    def test_prompt_toolkit_elevated_job_prompt_fragments(self):
        self.assertEqual(
            prompt_fragments("A12F", elevated=True),
            [
                ("class:prompt.name", "bl"),
                ("class:prompt.bracket", " ["),
                ("class:prompt.job", "#A12F"),
                ("class:prompt.arrow", "] # "),
            ],
        )

    def test_tagged_messages(self):
        output = io.StringIO()

        with redirect_stdout(output):
            info("scanning...", use_color=False)
            warn("rate limit detected", use_color=False)
            error("exploit failed", use_color=False)
            result("3 open ports", use_color=False)

        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "[info] scanning...",
                "[warn] rate limit detected",
                "[error] exploit failed",
                "[result] 3 open ports",
            ],
        )

    def test_colored_tag_labels(self):
        output = io.StringIO()

        with redirect_stdout(output):
            info("scanning...", use_color=True)
            result("3 ports found", use_color=True)
            warn("rate limit", use_color=True)
            error("failed", use_color=True)

        text = output.getvalue()
        self.assertIn("\033[38;5;51m[info]\033[0m", text)
        self.assertIn("\033[38;5;82m[result]\033[0m", text)
        self.assertIn("\033[38;5;214m[warn]\033[0m", text)
        self.assertIn("\033[38;5;196m[error]\033[0m", text)

    def test_section_colors_keys_and_values(self):
        output = io.StringIO()

        with redirect_stdout(output):
            section(
                "target",
                [
                    ("target", "192.168.1.1"),
                    ("ports", "22, 80"),
                ],
                use_color=True,
            )

        text = output.getvalue()
        self.assertIn("\033[38;5;245mtarget\033[0m", text)
        self.assertIn("\033[38;5;252m192.168.1.1\033[0m", text)
        self.assertIn("\033[38;5;245mports \033[0m", text)
        self.assertIn("\033[38;5;252m22, 80\033[0m", text)

    def test_job_id_is_cyan(self):
        output = io.StringIO()

        with redirect_stdout(output):
            job_id("#A12F", use_color=True)

        self.assertEqual(output.getvalue(), "\033[38;5;51m#A12F\033[0m\n")


if __name__ == "__main__":
    unittest.main()
