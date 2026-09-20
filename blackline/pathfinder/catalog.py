"""Declarative Pathfinder tool identity contracts."""

from __future__ import annotations

from blackline.config.tool_loader import get_recon_tool_registry_config, get_tool_config
from blackline.pathfinder.models import ToolSpec


def tool_spec(name: str, *, executable: str = "") -> ToolSpec:
    """Build a tool identity contract from Blackline's configured registry."""
    normalized = name.strip().lower()
    raw = next(
        (
            item
            for item in get_recon_tool_registry_config().get("tools", [])
            if isinstance(item, dict) and str(item.get("name", "")).strip().lower() == normalized
        ),
        {},
    )
    raw = raw if isinstance(raw, dict) else {}
    config = get_tool_config(normalized)
    identity = config.get("identity_markers", ()) if isinstance(config, dict) else ()
    return ToolSpec(
        name=normalized or executable.strip() or "tool",
        executable=executable.strip() or str(raw.get("binary") or config.get("binary") or normalized),
        provider=str(raw.get("provider", "")).strip(),
        check_args=_strings(raw.get("check_args")),
        check_success_codes=_integers(raw.get("check_success_codes"), default=(0,)),
        identity_markers=_strings(identity, lower=True),
    )


def _strings(value: object, *, lower: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    values = tuple(str(item).strip() for item in value if str(item).strip())
    return tuple(item.lower() for item in values) if lower else values


def _integers(value: object, *, default: tuple[int, ...]) -> tuple[int, ...]:
    if not isinstance(value, list):
        return default
    values: list[int] = []
    for item in value:
        try:
            values.append(int(item))
        except (TypeError, ValueError):
            continue
    return tuple(values) or default
