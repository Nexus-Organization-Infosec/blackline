import unittest

from blackline.tools.installer import install_tool, installation_plans, installable_tool_names
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


def command_result(command, *, returncode=0, stderr=""):
    return CommandResult(tuple(command), returncode, "", stderr, 0.01)


class ToolInstallerTests(unittest.TestCase):
    def test_names_are_loaded_from_declarative_config(self):
        self.assertEqual(installable_tool_names(config=CONFIG), ("sample",))

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


if __name__ == "__main__":
    unittest.main()
