"""User-facing inspection and preference commands for recon providers."""

from __future__ import annotations

from blackline.cli.ui.display import error, result, write_line
from blackline.core.recon.tool_registry import check_recon_tool, check_recon_tools, get_recon_tool, recon_tool_status, recon_tools, set_recon_tool_enabled


def handle_recon_tools(argument: str, *, use_color: bool | None = None) -> bool:
    """Handle ``recon tools`` without involving recon expression parsing."""
    words = argument.strip().split()
    if not words or words[0].lower() != "tools":
        return False
    if len(words) == 1:
        _render_tools("RECON TOOLS", use_color=use_color)
        return True
    action = words[1].lower()
    if action == "check" and len(words) == 2:
        _render_checks(use_color=use_color)
        return True
    if action == "show" and len(words) == 3:
        return _render_tool(words[2], use_color=use_color)
    if action in {"enable", "disable"} and len(words) == 3:
        tool = get_recon_tool(words[2])
        if tool is None:
            error(f"unknown recon tool: {words[2]}", use_color=use_color)
            return False
        set_recon_tool_enabled(tool.name, action == "enable")
        result(f"recon tool {tool.name} {action}d", use_color=use_color)
        return True
    error("usage: recon tools [show <tool> | check | enable <tool> | disable <tool>]", use_color=use_color)
    return False


def _render_tools(title: str, *, use_color: bool | None) -> None:
    tools = recon_tools()
    write_line(title, color="cyan", bold=True, use_color=use_color)
    write_line("─" * 64, color="muted", use_color=use_color)
    write_line(f"{'TOOL'.ljust(13)} {'CAPABILITY'.ljust(24)} {'STATUS'.ljust(13)} BACKEND", color="muted", use_color=use_color)
    for tool in tools:
        write_line(
            f"{tool.name.ljust(13)} {tool.capability.ljust(24)} {recon_tool_status(tool).ljust(13)} {tool.backend}",
            use_color=use_color,
        )


def _render_tool(name: str, *, use_color: bool | None) -> bool:
    tool = get_recon_tool(name)
    if tool is None:
        error(f"unknown recon tool: {name}", use_color=use_color)
        return False
    write_line(tool.name.upper(), color="cyan", bold=True, use_color=use_color)
    write_line("─" * 36, color="muted", use_color=use_color)
    health = check_recon_tool(tool)
    rows = (
        ("status", health.status),
        ("capability", tool.capability),
        ("backend", tool.backend),
        ("binary", tool.binary or "built in"),
        ("version", health.version or "unknown"),
        ("check", health.detail or "not checked"),
        ("strategies", ", ".join(tool.strategies) or "all"),
        ("produces", ", ".join(tool.produces) or "none"),
        ("consumes", ", ".join(tool.consumes) or "none"),
    )
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        write_line(f"{label.ljust(width)}  {value}", use_color=use_color)
    return True


def _render_checks(*, use_color: bool | None) -> None:
    checks = check_recon_tools()
    write_line("RECON TOOL CHECK", color="cyan", bold=True, use_color=use_color)
    write_line("─" * 76, color="muted", use_color=use_color)
    write_line(f"{'TOOL'.ljust(13)} {'STATUS'.ljust(13)} {'VERSION'.ljust(34)} DETAIL", color="muted", use_color=use_color)
    for check in checks:
        write_line(
            f"{check.tool.name.ljust(13)} {check.status.ljust(13)} {(check.version or '-').ljust(34)} {check.detail}",
            use_color=use_color,
        )
