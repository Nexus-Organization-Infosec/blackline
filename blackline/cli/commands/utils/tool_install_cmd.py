"""Thin CLI rendering for the declarative external-tool installer."""

from __future__ import annotations

from blackline.cli.ui.display import error, info, result, write_line
from blackline.tools.installer import install_tool, installable_tool_groups, installable_tool_names, tools_for_install_group


def handle_install(argument: str, *, use_color: bool | None = None) -> bool:
    """Install one optional tool after an explicit user command."""
    parts = argument.strip().lower().split()
    if not parts:
        available = ", ".join(installable_tool_names()) or "none"
        groups = ", ".join(installable_tool_groups()) or "none"
        error(f"usage: tools install <tool> [source] | tools install all [group] [source] [verbose] (tools: {available}; groups: {groups})", use_color=use_color)
        return False
    if parts[0] != "all":
        source = parts[1:] == ["source"]
        if len(parts) != 1 and not source:
            error("usage: tools install <tool> [source] | tools install all [group] [source] [verbose]", use_color=use_color)
            return False
        tool = parts[0]
        info(f"building {tool} from source" if source else f"installing {tool}", use_color=use_color)
        outcome = install_tool(tool, prefer_source=True) if source else install_tool(tool)
        if outcome.installed:
            result(outcome.message, use_color=use_color)
            return True
        error(outcome.message, use_color=use_color)
        return False

    verbose = "verbose" in parts[1:]
    source = "source" in parts[1:]
    selectors = [part for part in parts[1:] if part not in {"source", "verbose"}]
    if len(selectors) > 1:
        error("usage: tools install all [group] [source] [verbose]", use_color=use_color)
        return False
    group = selectors[0] if selectors else "all"
    tools = tools_for_install_group(group)
    if not tools:
        groups = ", ".join(installable_tool_groups()) or "none"
        error(f"unknown or empty install group: {group} (groups: {groups})", use_color=use_color)
        return False
    action = "building from source" if source else "installing"
    info(f"{action} {len(tools)} tools from {group}", use_color=use_color)
    failures = 0
    for tool in tools:
        outcome = install_tool(tool, prefer_source=True) if source else install_tool(tool)
        if outcome.installed:
            result(f"{tool}: {outcome.message}", use_color=use_color)
        else:
            failures += 1
            error(f"{tool}: {outcome.message}", use_color=use_color)
        if verbose:
            _render_output(tool, getattr(outcome, "output", ""), use_color=use_color)
    if failures:
        error(f"{len(tools) - failures}/{len(tools)} tools installed", use_color=use_color)
        return False
    result(f"installed {len(tools)} tools", use_color=use_color)
    return True


def _render_output(tool: str, output: str, *, use_color: bool | None) -> None:
    """Show raw installer output only when explicitly requested for debugging."""
    if not output.strip():
        return
    write_line(f"{tool} output:", color="muted", use_color=use_color)
    write_line(output.rstrip(), use_color=use_color)
