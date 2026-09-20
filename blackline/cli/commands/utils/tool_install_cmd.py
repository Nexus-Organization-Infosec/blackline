"""Thin CLI rendering for the declarative external-tool installer."""

from __future__ import annotations

from blackline.cli.ui.display import error, info, result
from blackline.tools.installer import install_tool, installable_tool_groups, installable_tool_names, tools_for_install_group


def handle_install(argument: str, *, use_color: bool | None = None) -> bool:
    """Install one optional tool after an explicit user command."""
    parts = argument.strip().lower().split()
    if not parts:
        available = ", ".join(installable_tool_names()) or "none"
        groups = ", ".join(installable_tool_groups()) or "none"
        error(f"usage: tools install <tool> | tools install all [group] (tools: {available}; groups: {groups})", use_color=use_color)
        return False
    if parts[0] != "all":
        if len(parts) != 1:
            error("usage: tools install <tool> | tools install all [group]", use_color=use_color)
            return False
        tool = parts[0]
        info(f"installing {tool}", use_color=use_color)
        outcome = install_tool(tool)
        if outcome.installed:
            result(outcome.message, use_color=use_color)
            return True
        error(outcome.message, use_color=use_color)
        return False

    if len(parts) > 2:
        error("usage: tools install all [group]", use_color=use_color)
        return False
    group = parts[1] if len(parts) == 2 else "all"
    tools = tools_for_install_group(group)
    if not tools:
        groups = ", ".join(installable_tool_groups()) or "none"
        error(f"unknown or empty install group: {group} (groups: {groups})", use_color=use_color)
        return False
    info(f"installing {len(tools)} tools from {group}", use_color=use_color)
    failures = 0
    for tool in tools:
        outcome = install_tool(tool)
        if outcome.installed:
            result(f"{tool}: {outcome.message}", use_color=use_color)
        else:
            failures += 1
            error(f"{tool}: {outcome.message}", use_color=use_color)
    if failures:
        error(f"{len(tools) - failures}/{len(tools)} tools installed", use_color=use_color)
        return False
    result(f"installed {len(tools)} tools", use_color=use_color)
    return True
