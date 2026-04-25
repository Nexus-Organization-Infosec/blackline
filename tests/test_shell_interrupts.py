import unittest
from unittest.mock import patch

from blackline.cli import core_shell


class ShellInterruptTests(unittest.TestCase):
    def test_ctrl_c_does_not_exit_shell(self):
        calls = {"count": 0}

        def fake_input(_prompt: str) -> str:
            calls["count"] += 1
            if calls["count"] == 1:
                raise KeyboardInterrupt
            if calls["count"] == 2:
                return "exit"
            raise AssertionError("unexpected extra prompt")

        with patch.object(core_shell, "create_prompt_session", return_value=None):
            with patch("builtins.input", side_effect=fake_input):
                result = core_shell.run_shell()

        self.assertEqual(result, 0)
        self.assertEqual(calls["count"], 2)


if __name__ == "__main__":
    unittest.main()
