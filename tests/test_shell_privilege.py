import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from blackline.cli import auth, core_shell
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.utils.exec import CommandResult


class _FakePromptSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def prompt(self, *args, **kwargs):
        self.calls.append({"args": args, "kwargs": kwargs})
        if not self._responses:
            raise AssertionError("unexpected extra password prompt")
        response = self._responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class ShellPrivilegeTests(unittest.TestCase):
    def test_ensure_elevated_session_authenticates_inline(self):
        prompt_session = _FakePromptSession([])
        state = ShellState(prompt_session=prompt_session)
        output = io.StringIO()

        with patch.object(auth, "_prompt_password_with_prompt_toolkit", return_value="secret") as password_prompt:
            with patch.object(auth, "run_command", return_value=CommandResult(("sudo", "-S", "-p", "", "-v"), 0, "", "", 0.1)):
                with redirect_stdout(output):
                    ok = auth.ensure_elevated_session(state, use_color=False)

        self.assertTrue(ok)
        self.assertTrue(state.sudo_authenticated)
        self.assertGreater(state.sudo_expires_at, 0.0)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "[auth] elevated privileges required",
                "[auth] validating...",
                "[auth] session authenticated",
            ],
        )
        password_prompt.assert_called_once_with()
        self.assertEqual(prompt_session.calls, [])

    def test_ensure_elevated_session_retries_incorrect_password(self):
        state = ShellState(prompt_session=_FakePromptSession([]))
        output = io.StringIO()
        responses = [
            CommandResult(("sudo", "-S", "-p", "", "-v"), 1, "", "Sorry, try again.", 0.1),
            CommandResult(("sudo", "-S", "-p", "", "-v"), 0, "", "", 0.1),
        ]

        with patch.object(auth, "_prompt_password_with_prompt_toolkit", side_effect=["wrong", "secret"]):
            with patch.object(auth, "run_command", side_effect=responses):
                with redirect_stdout(output):
                    ok = auth.ensure_elevated_session(state, use_color=False)

        self.assertTrue(ok)
        self.assertTrue(state.sudo_authenticated)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "[auth] elevated privileges required",
                "[auth] validating...",
                "[auth failed]",
                "incorrect password",
                "[auth] validating...",
                "[auth] session authenticated",
            ],
        )

    def test_dispatch_line_does_not_create_job_when_auth_fails(self):
        output = io.StringIO()
        created = {"count": 0}
        called = {"count": 0}
        original_handle_new = core_shell.dispatch_line.__globals__["handle_new"]
        original_handle_recon = core_shell.dispatch_line.__globals__["handle_recon"]

        def fake_handle_new(*args, **kwargs):
            created["count"] += 1
            return True

        def fake_handle_recon(*args, **kwargs):
            called["count"] += 1
            return True

        core_shell.dispatch_line.__globals__["handle_new"] = fake_handle_new
        core_shell.dispatch_line.__globals__["handle_recon"] = fake_handle_recon
        try:
            with patch.object(core_shell, "_recon_requires_elevation", return_value=True):
                with patch.object(core_shell, "ensure_elevated_session", return_value=False):
                    with redirect_stdout(output):
                        should_exit = core_shell.dispatch_line("recon[target=10.0.0.1,strategy=quiet]", ShellState())
        finally:
            core_shell.dispatch_line.__globals__["handle_new"] = original_handle_new
            core_shell.dispatch_line.__globals__["handle_recon"] = original_handle_recon

        self.assertFalse(should_exit)
        self.assertEqual(created["count"], 0)
        self.assertEqual(called["count"], 0)
        self.assertEqual(output.getvalue(), "")

    def test_dispatch_line_continues_after_authentication(self):
        output = io.StringIO()
        created = {"count": 0}
        called = {"active_job": ""}
        original_handle_new = core_shell.dispatch_line.__globals__["handle_new"]
        original_handle_recon = core_shell.dispatch_line.__globals__["handle_recon"]

        def fake_handle_new(expression, state, **kwargs):
            created["count"] += 1
            state.active_job = "A12F"
            return True

        def fake_handle_recon(expression, *, active_job="", use_color=None):
            called["active_job"] = active_job
            print("[result] fake recon")
            return True

        core_shell.dispatch_line.__globals__["handle_new"] = fake_handle_new
        core_shell.dispatch_line.__globals__["handle_recon"] = fake_handle_recon
        try:
            with patch.object(core_shell, "_recon_requires_elevation", return_value=True):
                with patch.object(core_shell, "ensure_elevated_session", return_value=True):
                    with redirect_stdout(output):
                        should_exit = core_shell.dispatch_line("recon[target=10.0.0.1,strategy=quiet]", ShellState())
        finally:
            core_shell.dispatch_line.__globals__["handle_new"] = original_handle_new
            core_shell.dispatch_line.__globals__["handle_recon"] = original_handle_recon

        self.assertFalse(should_exit)
        self.assertEqual(created["count"], 1)
        self.assertEqual(called["active_job"], "A12F")
        self.assertEqual(output.getvalue().strip(), "[result] fake recon")

    def test_exit_closes_elevated_session_before_leaving_job(self):
        state = ShellState(active_job="AC5S", sudo_authenticated=True, sudo_expires_at=float("inf"))
        output = io.StringIO()

        with patch.object(core_shell, "close_elevated_session", return_value=True) as close_mock:
            with redirect_stdout(output):
                should_exit = core_shell.dispatch_line("exit", state)

        self.assertFalse(should_exit)
        self.assertEqual(state.active_job, "AC5S")
        close_mock.assert_called_once()

    def test_exit_leaves_job_after_elevation_is_gone(self):
        state = ShellState(active_job="AC5S", sudo_authenticated=False, sudo_expires_at=0.0)
        output = io.StringIO()

        with redirect_stdout(output):
            should_exit = core_shell.dispatch_line("exit", state)

        self.assertFalse(should_exit)
        self.assertEqual(state.active_job, "")
        self.assertEqual(output.getvalue().strip(), "[info] left job #AC5S")

    def test_exit_terminates_base_shell(self):
        output = io.StringIO()

        with redirect_stdout(output):
            should_exit = core_shell.dispatch_line("exit", ShellState())

        self.assertTrue(should_exit)
        self.assertEqual(output.getvalue().strip(), "[shutdown] session terminated")

    def test_ctrl_d_unwinds_context_before_exiting_shell(self):
        calls = {"count": 0}
        state = ShellState(active_job="AC5S", sudo_authenticated=True, sudo_expires_at=float("inf"))

        def fake_input(_prompt: str) -> str:
            calls["count"] += 1
            if calls["count"] == 1:
                raise EOFError
            if calls["count"] == 2:
                raise EOFError
            if calls["count"] == 3:
                raise EOFError
            raise AssertionError("unexpected extra prompt")

        with patch.object(core_shell, "create_prompt_session", return_value=None):
            with patch.object(core_shell, "ShellState", return_value=state):
                with patch("builtins.input", side_effect=fake_input):
                    with patch.object(auth, "run_command", return_value=CommandResult(("sudo", "-k"), 0, "", "", 0.1)):
                        result = core_shell.run_shell()

        self.assertEqual(result, 0)
        self.assertEqual(calls["count"], 3)
        self.assertEqual(state.active_job, "")


if __name__ == "__main__":
    unittest.main()
