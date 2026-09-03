import unittest
from blackline.config.tool_loader import clear_tool_config_cache, get_tool_config
from blackline.tools.network.nmap import NmapRequest, build_nmap_command, display_command, execute_nmap
from blackline.tools.parsers.nmap import NmapParsedResult, parse_nmap_output
from blackline.utils.exec import CommandResult, run_command
from tests.fixture_loader import read_text


class NmapToolTests(unittest.TestCase):
    def test_build_nmap_command(self):
        command = build_nmap_command(
            NmapRequest(
                target="192.168.1.1",
                ports="80-443",
                timing="T4",
                service_detection=True,
                scripts=True,
                os_detection=True,
            )
        )

        self.assertEqual(
            command,
            ("nmap", "-Pn", "-T4", "-p", "80-443", "-sV", "-sC", "-O", "192.168.1.1"),
        )

    def test_build_nmap_command_uses_profile_config(self):
        command = build_nmap_command(
            NmapRequest(target="192.168.1.1", profile="stealth", top_ports="20"),
            config=get_tool_config("nmap"),
        )

        self.assertEqual(
            command,
            ("nmap", "-Pn", "-sS", "-T2", "--max-retries", "2", "--top-ports", "20", "192.168.1.1"),
        )

    def test_display_command_strips_non_interactive_sudo_flag(self):
        self.assertEqual(
            display_command(("sudo", "-n", "nmap", "-Pn", "10.0.0.1")),
            ("sudo", "nmap", "-Pn", "10.0.0.1"),
        )

    def test_build_nmap_command_uses_aggressive_profile(self):
        command = build_nmap_command(
            NmapRequest(target="example.com", profile="aggressive", timing="T5"),
            config=get_tool_config("nmap"),
        )

        self.assertEqual(command, ("nmap", "-Pn", "-T5", "-A", "-p", "1-1024", "example.com"))

    def test_parse_nmap_output(self):
        parsed = parse_nmap_output(read_text("nmap", "macos_ssh.txt"))

        self.assertEqual(parsed.target, "192.168.1.1")
        self.assertEqual(parsed.host_status, "up")
        self.assertEqual(len(parsed.ports), 2)
        self.assertEqual(parsed.ports[0].port, 22)
        self.assertEqual(parsed.ports[0].version, "OpenSSH 10.2")
        self.assertEqual(parsed.ports[1].state, "closed")
        self.assertEqual(parsed.device_type, "general purpose")
        self.assertEqual(parsed.operating_system, "Apple macOS 13.2 (Ventura)")
        self.assertEqual(parsed.kernel, "Darwin 22.3.0")
        self.assertEqual(parsed.cpe, "cpe:/o:apple:mac_os_x:13.2")
        self.assertEqual(parsed.distance, "0 hops")
        self.assertEqual(parsed.warnings, ("Warning: OSScan results may be unreliable",))

    def test_execute_nmap_with_fake_executor(self):
        def fake_executor(args: tuple[str, ...]) -> CommandResult:
            return CommandResult(
                args=args,
                returncode=0,
                stdout="Nmap scan report for example.com\nHost is up.\n443/tcp open https\n",
                stderr="",
                elapsed_seconds=49.96,
            )

        execution = execute_nmap(NmapRequest(target="example.com"), executor=fake_executor)

        self.assertTrue(execution.ok)
        self.assertEqual(execution.parsed.target, "example.com")
        self.assertEqual(execution.parsed.ports[0].service, "https")

    def test_execute_nmap_uses_sudo_for_privileged_profile(self):
        seen: dict[str, tuple[str, ...]] = {}

        def fake_executor(args: tuple[str, ...]) -> CommandResult:
            seen["args"] = args
            return CommandResult(
                args=args,
                returncode=0,
                stdout="Nmap scan report for 192.168.1.1\nHost is up.\n",
                stderr="",
                elapsed_seconds=0.5,
            )

        execution = execute_nmap(
            NmapRequest(target="192.168.1.1", profile="stealth", top_ports="20"),
            executor=fake_executor,
            config=get_tool_config("nmap"),
        )

        self.assertTrue(execution.ok)
        self.assertTrue(execution.used_sudo)
        self.assertEqual(
            seen["args"],
            ("sudo", "-n", "nmap", "-Pn", "-sS", "-T2", "--max-retries", "2", "--top-ports", "20", "192.168.1.1"),
        )

    def test_execute_nmap_without_binary_returns_error(self):
        from blackline.tools.network import nmap as nmap_module

        original_which = nmap_module.which
        nmap_module.which = lambda _: None
        try:
            execution = execute_nmap(NmapRequest(target="example.com"))
        finally:
            nmap_module.which = original_which

        self.assertFalse(execution.ok)
        self.assertEqual(execution.error, "nmap binary not found")
        self.assertEqual(execution.parsed, NmapParsedResult(target="example.com"))

    def test_execute_nmap_timeout_surfaces_detail(self):
        def fake_executor(args: tuple[str, ...]) -> CommandResult:
            return CommandResult(
                args=args,
                returncode=124,
                stdout="",
                stderr="command timed out after 120.0 seconds",
                elapsed_seconds=120.0,
            )

        execution = execute_nmap(
            NmapRequest(target="10.0.0.1"),
            executor=fake_executor,
            config=get_tool_config("nmap"),
        )

        self.assertFalse(execution.ok)
        self.assertEqual(execution.error, "command timed out after 120.0 seconds")

    def test_execute_nmap_default_executor_has_no_timeout_when_not_configured(self):
        seen: dict[str, float | None] = {}

        def fake_run_command(args: tuple[str, ...], *, timeout: float | None = 30.0) -> CommandResult:
            seen["timeout"] = timeout
            return CommandResult(args=args, returncode=0, stdout="", stderr="", elapsed_seconds=0.25)

        from blackline.tools.network import nmap as nmap_module

        original_run_command = nmap_module.run_command
        original_which = nmap_module.which
        nmap_module.run_command = fake_run_command
        nmap_module.which = lambda binary: binary
        try:
            execution = execute_nmap(NmapRequest(target="10.0.0.1"), executor=None, config=get_tool_config("nmap"))
        finally:
            nmap_module.run_command = original_run_command
            nmap_module.which = original_which

        self.assertTrue(execution.ok)
        self.assertIsNone(seen["timeout"])

    def test_execute_nmap_nonzero_exit_surfaces_stderr(self):
        def fake_executor(args: tuple[str, ...]) -> CommandResult:
            return CommandResult(
                args=args,
                returncode=2,
                stdout="",
                stderr="Failed to resolve target.",
                elapsed_seconds=0.2,
            )

        execution = execute_nmap(NmapRequest(target="example.com"), executor=fake_executor)

        self.assertFalse(execution.ok)
        self.assertEqual(execution.error, "nmap scan failed: Failed to resolve target.")

    def test_execute_nmap_sudo_auth_error_is_clean(self):
        def fake_executor(args: tuple[str, ...]) -> CommandResult:
            return CommandResult(
                args=args,
                returncode=1,
                stdout="",
                stderr="sudo: a password is required",
                elapsed_seconds=0.1,
            )

        execution = execute_nmap(
            NmapRequest(target="192.168.1.1", profile="stealth"),
            executor=fake_executor,
            config=get_tool_config("nmap"),
        )

        self.assertFalse(execution.ok)
        self.assertEqual(execution.error, "sudo authentication required for this scan; run 'sudo -v' and retry")

    def test_execute_nmap_timeout_returns_clean_error(self):
        result = run_command(("python", "-c", "import time; time.sleep(0.2)"), timeout=0.01)

        self.assertFalse(result.ok)
        self.assertEqual(result.returncode, 124)
        self.assertIn("timed out", result.stderr)
        self.assertGreater(result.elapsed_seconds, 0)

    def tearDown(self):
        clear_tool_config_cache()


if __name__ == "__main__":
    unittest.main()
