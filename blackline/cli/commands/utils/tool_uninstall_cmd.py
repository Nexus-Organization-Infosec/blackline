"""CLI rendering for explicit optional-tool removal."""

from __future__ import annotations

from blackline.cli.ui.display import error, info, result
from blackline.tools.installer import installable_tool_names, uninstall_tool


def handle_uninstall(argument: str, *, use_color: bool | None = None) -> bool:
    """Remove one configured optional tool, or every configured tool in turn."""
    parts = argument.strip().lower().split()
    if len(parts) != 1:
        error("usage: tools uninstall <tool|all>", use_color=use_color)
        return False
    available = installable_tool_names()
    names = available if parts[0] == "all" else (parts[0],)
    if not available:
        error("no uninstallable tools are configured", use_color=use_color)
        return False
    if parts[0] != "all" and parts[0] not in available:
        error(f"unknown tool: {parts[0]}", use_color=use_color)
        return False

    info(f"uninstalling {len(names)} tool{'s' if len(names) != 1 else ''}", use_color=use_color)
    failures = 0
    for name in names:
        outcome = uninstall_tool(name)
        if outcome.removed:
            result(f"{name}: {outcome.message}", use_color=use_color)
        else:
            failures += 1
            error(f"{name}: {outcome.message}", use_color=use_color)
    if failures:
        error(f"{len(names) - failures}/{len(names)} tools uninstalled", use_color=use_color)
        return False
    result(f"uninstalled {len(names)} tool{'s' if len(names) != 1 else ''}", use_color=use_color)
    return True
