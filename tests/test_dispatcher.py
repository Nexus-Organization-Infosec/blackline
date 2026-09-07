"""Regression coverage for the shared CLI command dispatcher."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from blackline.cli import cli, dispatcher
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.cli.core_shell import dispatch_line


class DispatcherTests(unittest.TestCase):
    def test_parser_preserves_recon_source_and_normalizes_regular_commands(self):
        parsed = dispatcher.parse_command("  recon [target= 10.0.0.1, strategy=deep]  ")
        self.assertEqual(parsed.name, "recon")
        self.assertEqual(parsed.argument, "recon [target= 10.0.0.1, strategy=deep]")
        self.assertEqual(parsed.raw, "recon [target= 10.0.0.1, strategy=deep]")

        parsed = dispatcher.parse_command("  SHOW   #A12F  ")
        self.assertEqual(parsed.name, "show")
        self.assertEqual(parsed.argument, "#A12F")

    def test_one_shot_entrypoint_delegates_to_dispatcher(self):
        expected = dispatcher.DispatchResult(exit_code=7)
        startup = [type("Startup", (), {"ok": True})()]
        with patch.object(cli, "run_startup_checks", return_value=startup), patch.object(cli, "render_startup"), patch.object(
            cli, "dispatch_command", return_value=expected
        ) as dispatch:
            result = cli.main(["-c", "help recon"])

        self.assertEqual(result, 7)
        self.assertEqual(dispatch.call_args.args[0], "help recon")
        self.assertIsInstance(dispatch.call_args.args[1], ShellState)

    def test_interactive_and_one_shot_dispatch_share_help_handler(self):
        calls: list[str] = []
        with patch.object(dispatcher, "handle_help", side_effect=calls.append):
            one_shot = dispatcher.dispatch_command("help recon", ShellState())
            interactive_exit = dispatch_line("help recon", ShellState())

        self.assertEqual(one_shot.exit_code, 0)
        self.assertFalse(interactive_exit)
        self.assertEqual(calls, ["recon", "recon"])

    def test_install_dispatches_through_the_shared_handler(self):
        with patch.object(dispatcher, "handle_install", return_value=True) as install:
            result = dispatcher.dispatch_command(" install  httpx ", ShellState())

        self.assertEqual(result.exit_code, 0)
        install.assert_called_once_with("httpx")

    def test_invalid_recon_is_reported_by_recon_handler_without_a_job(self):
        state = ShellState()
        with patch.object(dispatcher, "validate_recon_expression", return_value="invalid"), patch.object(
            dispatcher, "handle_new"
        ) as create_job, patch.object(dispatcher, "handle_recon", return_value=False) as recon:
            result = dispatcher.dispatch_command("recon[targe=10.0.0.1]", state)

        self.assertEqual(result.exit_code, 1)
        create_job.assert_not_called()
        recon.assert_called_once_with("recon[targe=10.0.0.1]", active_job="")

    def test_interactive_elevation_is_optional_lifecycle_behavior(self):
        with patch.object(dispatcher, "validate_recon_expression", return_value=""), patch.object(
            dispatcher, "requires_elevation", return_value=True
        ), patch.object(dispatcher, "ensure_elevated_session", return_value=False) as authenticate, patch.object(
            dispatcher, "handle_new", return_value=True
        ), patch.object(
            dispatcher, "handle_recon"
        ) as recon:
            one_shot = dispatcher.dispatch_command("recon[target=10.0.0.1]", ShellState())
            interactive = dispatcher.dispatch_command(
                "recon[target=10.0.0.1]", ShellState(), manage_elevation=True
            )

        self.assertEqual(one_shot.exit_code, 0)
        self.assertEqual(interactive.exit_code, 1)
        authenticate.assert_called_once()
        self.assertEqual(recon.call_count, 1)

    def test_exit_result_can_defer_to_interactive_context_unwinding(self):
        state = ShellState()
        one_shot = dispatcher.dispatch_command("exit", state)
        interactive = dispatcher.dispatch_command("exit", state, exit_context=lambda _state: False)

        self.assertTrue(one_shot.exit_shell)
        self.assertFalse(interactive.exit_shell)
