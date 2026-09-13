"""Top-level inspection for configured external and built-in tools."""

from __future__ import annotations

from shutil import which

from blackline.cli.ui.display import error, write_line
from blackline.config.tool_loader import get_tool_installer_config
from blackline.core.recon.tool_registry import check_recon_tool, get_recon_tool, recon_tool_status, recon_tools
from blackline.tools.installer import default_install_dir, installable_tool_names


def known_tool_names() -> tuple[str, ...]:
    """Return every known tool from the capability and installer registries."""
    return tuple(sorted({tool.name for tool in recon_tools()} | set(installable_tool_names())))


def handle_tools(argument: str = "", *, use_color: bool | None = None) -> bool:
    """Render all tools, a named collection, or one tool's operational details."""
    query = argument.strip().lower()
    if query in {"", "all"}:
        _render_tool_list(known_tool_names(), title="TOOLS", use_color=use_color)
        return True
    if query == "recon":
        _render_tool_list(tuple(tool.name for tool in recon_tools()), title="RECON TOOLS", use_color=use_color)
        return True
    if " " in query:
        error("usage: tools [recon|<tool>]", use_color=use_color)
        return False
    if query not in known_tool_names():
        error(f"unknown tool: {query}", use_color=use_color)
        return False
    _render_tool_details(query, use_color=use_color)
    return True


def _render_tool_list(names: tuple[str, ...], *, title: str, use_color: bool | None) -> None:
    """Render a compact type-and-status overview without running external commands."""
    write_line(title, color="cyan", bold=True, use_color=use_color)
    write_line("─" * 54, color="muted", use_color=use_color)
    write_line(f"{'TOOL'.ljust(13)} {'TYPE'.ljust(24)} STATUS", color="muted", use_color=use_color)
    for name in names:
        tool = get_recon_tool(name)
        capability = tool.capability if tool else "optional external tool"
        status = recon_tool_status(tool) if tool else ("ready" if _installed_location(name) else "unavailable")
        write_line(f"{name.ljust(13)} {capability.ljust(24)} {status}", use_color=use_color)


def _render_tool_details(name: str, *, use_color: bool | None) -> None:
    """Render capability, installation, and build-route details for one tool."""
    recon_tool = get_recon_tool(name)
    binary = recon_tool.binary if recon_tool and recon_tool.binary else name
    location = _installed_location(binary)
    write_line(name.upper(), color="cyan", bold=True, use_color=use_color)
    write_line("─" * 48, color="muted", use_color=use_color)
    rows: list[tuple[str, str]] = [("binary", binary), ("installed", location or "not installed")]
    if recon_tool:
        health = check_recon_tool(recon_tool)
        rows.extend(
            [
                ("status", health.status),
                ("version", health.version or "unknown"),
                ("capability", recon_tool.capability),
                ("backend", recon_tool.backend),
                ("strategies", ", ".join(recon_tool.strategies) or "all"),
                ("produces", ", ".join(recon_tool.produces) or "none"),
                ("consumes", ", ".join(recon_tool.consumes) or "none"),
            ]
        )
    rows.extend(_installer_rows(name))
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        write_line(f"{label.ljust(width)}  {value}", use_color=use_color)


def _installed_location(binary: str) -> str:
    """Find a binary on PATH or in Blackline's user-local build directory."""
    path = which(binary)
    if path:
        return path
    local_path = default_install_dir() / binary
    return str(local_path) if local_path.exists() else ""


def _installer_rows(name: str) -> list[tuple[str, str]]:
    """Describe package and source-build choices without executing them."""
    if name not in installable_tool_names():
        return [("installer", "not configured")]
    config = get_tool_installer_config()
    recipe = config.get("tools", {}).get(name, {}) if isinstance(config.get("tools", {}), dict) else {}
    if not isinstance(recipe, dict):
        return [("installer", "not configured")]
    platforms = recipe.get("platforms", {})
    source_builds = recipe.get("source_builds", {})
    package_managers = sorted(
        {
            str(route.get("manager") or route.get("manager_binary"))
            for routes in platforms.values()
            if isinstance(platforms, dict) and isinstance(routes, list)
            for route in routes
            if isinstance(route, dict) and (route.get("manager") or route.get("manager_binary"))
        }
    ) if isinstance(platforms, dict) else []
    source_managers = sorted(
        {
            str(route.get("manager") or "source build")
            for routes in source_builds.values()
            if isinstance(source_builds, dict) and isinstance(routes, list)
            for route in routes
            if isinstance(route, dict)
        }
    ) if isinstance(source_builds, dict) else []
    supported = sorted(set(platforms) | set(source_builds)) if isinstance(platforms, dict) and isinstance(source_builds, dict) else []
    rows = [("platforms", ", ".join(supported) or "none")]
    if package_managers:
        rows.append(("install routes", ", ".join(package_managers)))
    if source_managers:
        rows.append(("source builds", ", ".join(source_managers)))
    rows.append(("install", f"install {name}"))
    return rows
