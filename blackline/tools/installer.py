"""Declarative, platform-aware installation for optional external tools."""

from __future__ import annotations

from dataclasses import dataclass
from platform import system as current_system
from pathlib import Path
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
class SourceBuildPlan:
    """One repository clone-and-build route for an external tool."""

    tool: str
    binary: str
    platform: str
    manager: str
    repository: str
    ref: str
    required_binaries: tuple[str, ...]
    build_commands: tuple[tuple[str, ...], ...]


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


def installable_tool_groups(*, config: dict | None = None) -> tuple[str, ...]:
    """Return named groups whose members have installation recipes."""
    config = config or get_tool_installer_config()
    groups = config.get("groups", {}) if isinstance(config, dict) else {}
    available = set(installable_tool_names(config=config))
    if not isinstance(groups, dict):
        return ()
    return tuple(
        sorted(
            str(name).lower()
            for name, members in groups.items()
            if isinstance(members, list) and any(str(member).lower() in available for member in members)
        )
    )


def tools_for_install_group(group: str = "", *, config: dict | None = None) -> tuple[str, ...]:
    """Return configured tools for a group, or every configured tool for ``all``."""
    normalized = group.strip().lower()
    if normalized in {"", "all"}:
        return installable_tool_names(config=config)
    config = config or get_tool_installer_config()
    groups = config.get("groups", {}) if isinstance(config, dict) else {}
    members = groups.get(normalized, ()) if isinstance(groups, dict) else ()
    available = set(installable_tool_names(config=config))
    if not isinstance(members, list):
        return ()
    return tuple(sorted({str(member).lower() for member in members if str(member).lower() in available}))


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


def source_build_plans(
    tool: str,
    *,
    platform_name: str | None = None,
    config: dict | None = None,
    executable_resolver: Callable[[str], str | None] = which,
) -> tuple[SourceBuildPlan, ...]:
    """Return clone-and-build routes whose local prerequisites are available."""
    config = config or get_tool_installer_config()
    tools = config.get("tools", {}) if isinstance(config, dict) else {}
    recipe = tools.get(tool, {}) if isinstance(tools, dict) else {}
    if not isinstance(recipe, dict):
        return ()
    platform_name = platform_name or current_system()
    binary = str(recipe.get("binary") or tool)
    builds = recipe.get("source_builds", {})
    routes = builds.get(platform_name, ()) if isinstance(builds, dict) else ()
    if not isinstance(routes, list):
        return ()

    plans: list[SourceBuildPlan] = []
    for route in routes:
        if not isinstance(route, dict):
            continue
        repository = str(route.get("repository", "")).strip()
        commands = route.get("build_commands", ())
        required = route.get("required_binaries", ("git",))
        if not isinstance(commands, list) or not commands or not isinstance(required, list) or not repository:
            continue
        required_binaries = tuple(str(item).strip() for item in required if str(item).strip())
        if not required_binaries or any(executable_resolver(item) is None for item in required_binaries):
            continue
        normalized_commands: list[tuple[str, ...]] = []
        for command in commands:
            if not isinstance(command, list) or not command:
                normalized_commands = []
                break
            normalized_commands.append(tuple(str(part) for part in command))
        if not normalized_commands:
            continue
        plans.append(
            SourceBuildPlan(
                tool=tool,
                binary=binary,
                platform=platform_name,
                manager=str(route.get("manager") or "source build"),
                repository=repository,
                ref=str(route.get("ref") or ""),
                required_binaries=required_binaries,
                build_commands=tuple(normalized_commands),
            )
        )
    return tuple(plans)


def default_source_root() -> Path:
    """Return the user-local directory used for checked-out tool sources."""
    return Path.home() / ".local" / "share" / "blackline" / "tools"


def default_install_dir() -> Path:
    """Return the user-local directory used for built tool binaries."""
    return Path.home() / ".local" / "bin"


def install_tool(
    tool: str,
    *,
    platform_name: str | None = None,
    config: dict | None = None,
    executable_resolver: Callable[[str], str | None] = which,
    executor: Callable[[tuple[str, ...]], CommandResult] = run_command,
    build_executor: Callable[[tuple[str, ...], Path], CommandResult] | None = None,
    source_root: Path | None = None,
    install_dir: Path | None = None,
) -> ToolInstallResult:
    """Install a tool through a local manager or a declared source-build fallback.

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

    source_plans = source_build_plans(
        normalized,
        platform_name=platform_name,
        config=config,
        executable_resolver=executable_resolver,
    )
    source_root = source_root or default_source_root()
    install_dir = install_dir or default_install_dir()
    build_executor = build_executor or (lambda command, cwd: run_command(command, cwd=cwd, timeout=None))
    for plan in source_plans:
        outcome = _install_from_source(
            plan,
            source_root=source_root,
            install_dir=install_dir,
            executable_resolver=executable_resolver,
            executor=executor,
            build_executor=build_executor,
        )
        if outcome.installed:
            return outcome
        failures.append(f"{plan.manager}: {outcome.message}")

    if not plans and not source_plans:
        platform_label = platform_name or current_system()
        return ToolInstallResult(normalized, binary, message=f"no supported installer is available for {binary} on {platform_label}")

    first = plans[0] if plans else source_plans[0]
    return ToolInstallResult(
        normalized,
        binary,
        attempted=True,
        manager=first.manager,
        command=first.command if isinstance(first, ToolInstallPlan) else first.build_commands[-1],
        message=f"could not install {binary} ({'; '.join(failures)})",
    )


def _install_from_source(
    plan: SourceBuildPlan,
    *,
    source_root: Path,
    install_dir: Path,
    executable_resolver: Callable[[str], str | None],
    executor: Callable[[tuple[str, ...]], CommandResult],
    build_executor: Callable[[tuple[str, ...], Path], CommandResult],
) -> ToolInstallResult:
    """Clone or refresh one source tree, then run its configured build commands."""
    source_dir = source_root / plan.tool
    try:
        source_root.mkdir(parents=True, exist_ok=True)
        install_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return ToolInstallResult(plan.tool, plan.binary, manager=plan.manager, message=f"could not prepare local install directories: {exc}")

    if source_dir.exists():
        if not source_dir.is_dir() or not (source_dir / ".git").is_dir():
            return ToolInstallResult(plan.tool, plan.binary, manager=plan.manager, message=f"source directory is not a Git checkout: {source_dir}")
        checkout = executor(("git", "-C", str(source_dir), "fetch", "--depth", "1", "origin", plan.ref or "HEAD"))
        action = "update"
    else:
        clone_command = ["git", "clone", "--depth", "1"]
        if plan.ref:
            clone_command.extend(["--branch", plan.ref])
        clone_command.extend([plan.repository, str(source_dir)])
        checkout = executor(tuple(clone_command))
        action = "clone"
    if not checkout.ok:
        detail = checkout.stderr.strip() or f"exit {checkout.returncode}"
        return ToolInstallResult(plan.tool, plan.binary, attempted=True, manager=plan.manager, command=checkout.args, message=f"could not {action} source repository: {detail}")

    if action == "update":
        checkout = executor(("git", "-C", str(source_dir), "checkout", "--detach", "FETCH_HEAD"))
        if not checkout.ok:
            detail = checkout.stderr.strip() or f"exit {checkout.returncode}"
            return ToolInstallResult(plan.tool, plan.binary, attempted=True, manager=plan.manager, command=checkout.args, message=f"could not update source repository: {detail}")

    last_command: tuple[str, ...] = ()
    for command in plan.build_commands:
        rendered = tuple(part.format(source_dir=str(source_dir), install_dir=str(install_dir), binary=plan.binary) for part in command)
        last_command = rendered
        result = build_executor(rendered, source_dir)
        if not result.ok:
            detail = result.stderr.strip() or f"exit {result.returncode}"
            return ToolInstallResult(plan.tool, plan.binary, attempted=True, manager=plan.manager, command=rendered, message=f"source build failed: {detail}")

    available = executable_resolver(plan.binary) is not None
    installed_path = install_dir / plan.binary
    if not available and installed_path.exists():
        available = True
    message = f"installed {plan.binary} from {plan.repository} with {plan.manager}"
    if not available:
        message += f"; add {install_dir} to PATH or restart the shell"
    return ToolInstallResult(plan.tool, plan.binary, attempted=True, installed=True, available=available, manager=plan.manager, command=last_command, message=message)
