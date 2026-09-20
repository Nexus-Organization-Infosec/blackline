import io
import unittest
from contextlib import redirect_stdout

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from blackline.cli.commands.utils.tool_install_cmd import handle_install
from blackline.cli.commands.utils.tool_uninstall_cmd import handle_uninstall
from blackline.tools.installer import (
    install_tool,
    installation_plans,
    installable_tool_names,
    source_build_plans,
    tools_for_install_group,
    uninstall_tool,
    uninstallation_plans,
)
from blackline.utils.exec import CommandResult


CONFIG = {
    "tools": {
        "sample": {
            "binary": "sample-bin",
            "platforms": {
                "Darwin": [
                    {"manager": "Homebrew", "manager_binary": "brew", "command": ["brew", "install", "sample"]},
                    {"manager": "Go", "manager_binary": "go", "command": ["go", "install", "example/sample@latest"]},
                ]
            },
        }
    }
}

SOURCE_CONFIG = {
    "tools": {
        "source-sample": {
            "binary": "source-sample",
            "source_builds": {
                "Darwin": [{
                    "manager": "Git + Make",
                    "repository": "https://example.test/source-sample.git",
                    "ref": "v1.2.3",
                    "required_binaries": ["git", "make"],
                    "build_commands": [["make", "install", "PREFIX={install_dir}"]],
                }]
            },
        }
    }
}


def command_result(command, *, returncode=0, stderr=""):
    return CommandResult(tuple(command), returncode, "", stderr, 0.01)


class ToolInstallerTests(unittest.TestCase):
    def test_names_are_loaded_from_declarative_config(self):
        self.assertEqual(installable_tool_names(config=CONFIG), ("sample",))

    def test_group_selects_configured_members_and_all_selects_everything(self):
        config = {**CONFIG, "groups": {"recon": ["sample", "missing"]}}
        self.assertEqual(tools_for_install_group("recon", config=config), ("sample",))
        self.assertEqual(tools_for_install_group(config=config), ("sample",))

    def test_selects_first_available_manager_in_recipe_order(self):
        plans = installation_plans(
            "sample",
            platform_name="Darwin",
            config=CONFIG,
            executable_resolver=lambda name: "/usr/local/bin/brew" if name == "brew" else None,
        )
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].manager, "Homebrew")
        self.assertEqual(plans[0].command, ("brew", "install", "sample"))

    def test_install_uses_selected_manager_and_confirms_availability(self):
        installed = {"value": False}

        def resolver(name):
            if name == "brew":
                return "/usr/local/bin/brew"
            return "/usr/local/bin/sample-bin" if installed["value"] and name == "sample-bin" else None

        def executor(command):
            installed["value"] = True
            return command_result(command)

        outcome = install_tool("sample", platform_name="Darwin", config=CONFIG, executable_resolver=resolver, executor=executor)
        self.assertTrue(outcome.attempted)
        self.assertTrue(outcome.installed)
        self.assertTrue(outcome.available)
        self.assertEqual(outcome.command, ("brew", "install", "sample"))

    def test_reports_missing_package_manager_without_attempting_install(self):
        outcome = install_tool(
            "sample",
            platform_name="Darwin",
            config=CONFIG,
            executable_resolver=lambda _name: None,
            executor=lambda _command: self.fail("installer should not run without a manager"),
        )
        self.assertFalse(outcome.attempted)
        self.assertIn("no supported installer", outcome.message)

    def test_reports_failed_install(self):
        outcome = install_tool(
            "sample",
            platform_name="Darwin",
            config=CONFIG,
            executable_resolver=lambda name: "/usr/local/bin/brew" if name == "brew" else None,
            executor=lambda command: command_result(command, returncode=1, stderr="network unavailable"),
        )
        self.assertTrue(outcome.attempted)
        self.assertFalse(outcome.installed)
        self.assertIn("network unavailable", outcome.message)

    def test_source_plan_requires_its_build_dependencies(self):
        plans = source_build_plans(
            "source-sample", platform_name="Darwin", config=SOURCE_CONFIG,
            executable_resolver=lambda name: f"/usr/bin/{name}" if name in {"git", "make"} else None,
        )
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].repository, "https://example.test/source-sample.git")

    def test_source_install_clones_then_builds_into_user_local_bin(self):
        commands = []
        available = {"value": False}

        def resolver(name):
            if name in {"git", "make"}:
                return f"/usr/bin/{name}"
            return "/tmp/source-sample" if name == "source-sample" and available["value"] else None

        def executor(command):
            commands.append(("checkout", command))
            return command_result(command)

        def builder(command, cwd):
            commands.append(("build", command, cwd))
            available["value"] = True
            return command_result(command)

        with TemporaryDirectory() as directory:
            root = Path(directory)
            outcome = install_tool(
                "source-sample", platform_name="Darwin", config=SOURCE_CONFIG,
                executable_resolver=resolver, executor=executor, build_executor=builder,
                source_root=root / "sources", install_dir=root / "bin",
            )

        self.assertTrue(outcome.installed)
        self.assertTrue(outcome.available)
        self.assertEqual(commands[0][1][:4], ("git", "clone", "--depth", "1"))
        self.assertEqual(commands[1][0], "build")
        self.assertIn("PREFIX=", commands[1][1][-1])

    def test_source_build_is_used_after_a_package_manager_failure(self):
        config = {
            "tools": {
                "source-sample": {
                    **SOURCE_CONFIG["tools"]["source-sample"],
                    "platforms": {"Darwin": [{"manager": "Broken manager", "manager_binary": "brew", "command": ["brew", "install", "source-sample"]}]},
                }
            }
        }
        events = []

        def resolver(name):
            return f"/usr/bin/{name}" if name in {"brew", "git", "make"} else None

        def executor(command):
            events.append(command)
            return command_result(command, returncode=1, stderr="unavailable") if command[0] == "brew" else command_result(command)

        with TemporaryDirectory() as directory:
            root = Path(directory)
            outcome = install_tool(
                "source-sample", platform_name="Darwin", config=config, executable_resolver=resolver,
                executor=executor, build_executor=lambda command, _cwd: command_result(command),
                source_root=root / "sources", install_dir=root / "bin",
            )

        self.assertTrue(outcome.installed)
        self.assertEqual(events[0][0], "brew")
        self.assertEqual(events[1][0], "git")

    def test_uninstall_uses_the_inverse_of_a_configured_package_route(self):
        plans = uninstallation_plans(
            "sample",
            platform_name="Darwin",
            config=CONFIG,
            executable_resolver=lambda name: "/usr/local/bin/brew" if name == "brew" else None,
        )

        self.assertEqual(plans[0].command, ("brew", "uninstall", "sample"))

    def test_uninstall_removes_only_blackline_managed_source_artifacts(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source_dir = root / "sources" / "source-sample"
            source_dir.mkdir(parents=True)
            (source_dir / "README.md").write_text("managed", encoding="utf-8")
            binary = root / "bin" / "source-sample"
            binary.parent.mkdir()
            binary.write_text("managed", encoding="utf-8")

            outcome = uninstall_tool(
                "source-sample",
                platform_name="Darwin",
                config=SOURCE_CONFIG,
                executable_resolver=lambda _name: None,
                source_root=root / "sources",
                install_dir=root / "bin",
            )

            self.assertTrue(outcome.removed)
            self.assertFalse(source_dir.exists())
            self.assertFalse(binary.exists())

    def test_uninstall_does_not_guess_at_go_workspace_binaries(self):
        config = {
            "tools": {
                "go-tool": {
                    "binary": "go-tool",
                    "platforms": {"Darwin": [{"manager": "Go", "manager_binary": "go", "command": ["go", "install", "example/go-tool@latest"]}]},
                }
            }
        }

        outcome = uninstall_tool(
            "go-tool",
            platform_name="Darwin",
            config=config,
            executable_resolver=lambda name: "/usr/local/bin/go" if name == "go" else None,
        )

        self.assertFalse(outcome.removed)
        self.assertIn("Go-managed binaries", outcome.message)

    def test_install_all_continues_after_one_tool_fails(self):
        success = type("Outcome", (), {"installed": True, "message": "installed"})()
        failure = type("Outcome", (), {"installed": False, "message": "missing dependency"})()
        output = io.StringIO()
        with patch("blackline.cli.commands.utils.tool_install_cmd.tools_for_install_group", return_value=("httpx", "naabu")), patch(
            "blackline.cli.commands.utils.tool_install_cmd.install_tool", side_effect=(success, failure)
        ) as install:
            with redirect_stdout(output):
                completed = handle_install("all recon", use_color=False)

        self.assertFalse(completed)
        self.assertEqual(install.call_args_list[0].args, ("httpx",))
        self.assertEqual(install.call_args_list[1].args, ("naabu",))
        self.assertIn("1/2 tools installed", output.getvalue())

    def test_uninstall_all_continues_after_one_tool_fails(self):
        success = type("Outcome", (), {"removed": True, "message": "removed"})()
        failure = type("Outcome", (), {"removed": False, "message": "not installed"})()
        output = io.StringIO()
        with patch("blackline.cli.commands.utils.tool_uninstall_cmd.installable_tool_names", return_value=("httpx", "naabu")), patch(
            "blackline.cli.commands.utils.tool_uninstall_cmd.uninstall_tool", side_effect=(success, failure)
        ) as uninstall:
            with redirect_stdout(output):
                completed = handle_uninstall("all", use_color=False)

        self.assertFalse(completed)
        self.assertEqual(uninstall.call_args_list[0].args, ("httpx",))
        self.assertEqual(uninstall.call_args_list[1].args, ("naabu",))
        self.assertIn("1/2 tools uninstalled", output.getvalue())


if __name__ == "__main__":
    unittest.main()
