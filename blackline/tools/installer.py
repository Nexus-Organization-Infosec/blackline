"""Declarative, platform-aware installation for optional external tools."""

from __future__ import annotations

from dataclasses import dataclass
from platform import system as current_system
from shutil import which
from typing import Callable

from blackline.config.tool_loader import get_tool_installer_config
from blackline.utils.exec import CommandResult, run_command


@dataclass(frozen=True, slots=True)
class ToolInstallPlan:
    """One supported installation route for a configured external tool."""

    tool: str
    binary: str
    platform: str
    manager: str
    command: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ToolInstallResult:
    """Structured result of an explicit tool-install request."""

    tool: str
    binary: str
    attempted: bool = False
    installed: bool = False
    available: bool = False
    manager: str = ""
    command: tuple[str, ...] = ()
    message: str = ""


def installable_tool_names(*, config: dict | None = None) -> tuple[str, ...]:
    """Return tools that have declarative installation recipes."""
    config = config or get_tool_installer_config()
    tools = config.get("tools", {}) if isinstance(config, dict) else {}
    return tuple(sorted(str(name) for name, recipe in tools.items() if isinstance(recipe, dict))) if isinstance(tools, dict) else ()


def installation_plans(
    tool: str,
    *,
    platform_name: str | None = None,
    config: dict | None = None,
    executable_resolver: Callable[[str], str | None] = which,
) -> tuple[ToolInstallPlan, ...]:
    """Return usable package-manager routes in declared preference order."""
    config = config or get_tool_installer_config()
    tools = config.get("tools", {}) if isinstance(config, dict) else {}
    recipe = tools.get(tool, {}) if isinstance(tools, dict) else {}
    if not isinstance(recipe, dict):
        return ()
    platform_name = platform_name or current_system()
    binary = str(recipe.get("binary") or tool)
    platforms = recipe.get("platforms", {})
    routes = platforms.get(platform_name, ()) if isinstance(platforms, dict) else ()
    if not isinstance(routes, list):
        return ()
    plans: list[ToolInstallPlan] = []
    for route in routes:
        if not isinstance(route, dict):
            continue
        manager_binary = str(route.get("manager_binary", "")).strip()
        command = route.get("command", ())
        if not manager_binary or not isinstance(command, list) or not command or executable_resolver(manager_binary) is None:
            continue
        plans.append(
            ToolInstallPlan(
                tool=tool,
                binary=binary,
                platform=platform_name,
                manager=str(route.get("manager") or manager_binary),
                command=tuple(str(part) for part in command),
            )
        )
    return tuple(plans)


def install_tool(
    tool: str,
    *,
    platform_name: str | None = None,
    config: dict | None = None,
    executable_resolver: Callable[[str], str | None] = which,
    executor: Callable[[tuple[str, ...]], CommandResult] = run_command,
) -> ToolInstallResult:
    """Install a configured tool through the first supported local manager.

    This function is intentionally called only through an explicit user action.
    It never invokes a shell, and recipes live in ``config/tool_installers.json``.
    """
    normalized = tool.strip().lower()
    config = config or get_tool_installer_config()
    tools = config.get("tools", {}) if isinstance(config, dict) else {}
    recipe = tools.get(normalized, {}) if isinstance(tools, dict) else {}
    if not isinstance(recipe, dict):
        return ToolInstallResult(normalized, normalized, message=f"no installer is configured for {normalized or 'that tool'}")
    binary = str(recipe.get("binary") or normalized)
    if executable_resolver(binary):
        return ToolInstallResult(normalized, binary, installed=True, available=True, message=f"{binary} is already available")

    plans = installation_plans(
        normalized,
        platform_name=platform_name,
        config=config,
        executable_resolver=executable_resolver,
    )
    if not plans:
        platform_label = platform_name or current_system()
        return ToolInstallResult(normalized, binary, message=f"no supported installer is available for {binary} on {platform_label}")

    failures: list[str] = []
    for plan in plans:
        result = executor(plan.command)
        if result.ok:
            available = executable_resolver(binary) is not None
            message = f"installed {binary} with {plan.manager}"
            if not available:
                message += f"; restart the shell or add its install location to PATH"
            return ToolInstallResult(
                normalized,
                binary,
                attempted=True,
                installed=True,
                available=available,
                manager=plan.manager,
                command=plan.command,
                message=message,
            )
        detail = result.stderr.strip() or f"exit {result.returncode}"
        failures.append(f"{plan.manager}: {detail}")

    first = plans[0]
    return ToolInstallResult(
        normalized,
        binary,
        attempted=True,
        manager=first.manager,
        command=first.command,
        message=f"could not install {binary} ({'; '.join(failures)})",
    )
