"""Thin CLI rendering for the declarative external-tool installer."""

from __future__ import annotations

from blackline.cli.ui.display import error, info, result
from blackline.tools.installer import install_tool, installable_tool_names


def handle_install(argument: str, *, use_color: bool | None = None) -> bool:
    """Install one optional tool after an explicit user command."""
    tool = argument.strip().lower()
    if not tool:
        available = ", ".join(installable_tool_names()) or "none"
        error(f"usage: install <tool> (available: {available})", use_color=use_color)
        return False
    info(f"installing {tool}", use_color=use_color)
    outcome = install_tool(tool)
    if outcome.installed:
        result(outcome.message, use_color=use_color)
        return True
    error(outcome.message, use_color=use_color)
    return False
