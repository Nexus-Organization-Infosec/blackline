"""Declarative recon capability registry shared by CLI and planning layers."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re

from blackline.config.tool_loader import get_recon_tool_registry_config
from blackline.pathfinder import Pathfinder


@dataclass(frozen=True, slots=True)
class ReconTool:
    """One provider's complete planning and execution contract."""

    name: str
    capability: str
    backend: str
    handler: str
    lifecycle: str = "active"
    binary: str = ""
    provider: str = ""
    produces: tuple[str, ...] = ()
    consumes: tuple[str, ...] = ()
    strategies: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    check_args: tuple[str, ...] = ()
    check_success_codes: tuple[int, ...] = (0,)
    timeout_seconds: float | None = None
    priority: int = 100


@dataclass(frozen=True, slots=True)
class ReconToolCheck:
    """Result of a bounded, non-network provider health probe."""

    tool: ReconTool
    status: str
    version: str = ""
    detail: str = ""
    path: str = ""


def recon_tools() -> tuple[ReconTool, ...]:
    """Return every registered recon provider in deterministic display order."""
    raw_tools = get_recon_tool_registry_config().get("tools", [])
    if not isinstance(raw_tools, list):
        return ()
    tools: list[ReconTool] = []
    for raw in raw_tools:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name", "")).strip().lower()
        capability = str(raw.get("capability", "")).strip()
        backend = str(raw.get("backend", "")).strip().lower()
        if not name or not capability or not backend:
            continue
        tools.append(
            ReconTool(
                name=name,
                capability=capability,
                backend=backend,
                handler=str(raw.get("handler", name)).strip().lower(),
                lifecycle=str(raw.get("lifecycle", "active")).strip().lower(),
                binary=str(raw.get("binary", "")).strip(),
                provider=str(raw.get("provider", "")).strip(),
                produces=_words(raw.get("produces")),
                consumes=_words(raw.get("consumes")),
                strategies=_words(raw.get("strategies")),
                dependencies=_words(raw.get("dependencies")),
                check_args=_words(raw.get("check_args")),
                check_success_codes=_integers(raw.get("check_success_codes"), default=(0,)),
                timeout_seconds=_positive_float(raw.get("timeout_seconds")),
                priority=_integer(raw.get("priority"), default=100),
            )
        )
    return tuple(tools)


def get_recon_tool(name: str) -> ReconTool | None:
    """Resolve one registered provider by its stable tool name."""
    normalized = name.strip().lower()
    return next((tool for tool in recon_tools() if tool.name == normalized), None)


def providers_for(product: str, *, strategy: str = "") -> tuple[ReconTool, ...]:
    """Find enabled providers capable of producing one normalized fact type."""
    return _ordered_providers(
        tool
        for tool in recon_tools()
        if tool.lifecycle == "active" and product in tool.produces and is_recon_tool_enabled(tool.name) and tool_supports_strategy(tool, strategy)
    )


def providers_for_capability(capability: str, *, strategy: str = "") -> tuple[ReconTool, ...]:
    """Return enabled providers for one canonical capability in priority order."""
    normalized = capability.strip().lower()
    return _ordered_providers(
        tool
        for tool in recon_tools()
        if tool.lifecycle == "active" and tool.capability == normalized and is_recon_tool_enabled(tool.name) and tool_supports_strategy(tool, strategy)
    )


def tool_supports_strategy(tool: ReconTool, strategy: str) -> bool:
    """Return whether a provider participates in the requested strategy."""
    normalized = strategy.strip().lower()
    return not normalized or not tool.strategies or normalized in tool.strategies


def validate_recon_tool_registry(*, handler_names: tuple[str, ...] | None = None) -> tuple[str, ...]:
    """Return deterministic configuration errors without touching the network."""
    errors: list[str] = []
    tools = recon_tools()
    names = [tool.name for tool in tools]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    errors.extend(f"duplicate provider: {name}" for name in duplicates)
    known_handlers = set(handler_names) if handler_names is not None else None
    valid_backends = {"native", "external", "service"}
    valid_lifecycles = {"active", "planned"}
    valid_strategies = {"surface", "fast", "balanced", "quiet", "deep", "udp", "auto"}
    for tool in tools:
        if not re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+", tool.capability):
            errors.append(f"{tool.name}: invalid capability {tool.capability!r}")
        if tool.backend not in valid_backends:
            errors.append(f"{tool.name}: invalid backend {tool.backend!r}")
        if tool.lifecycle not in valid_lifecycles:
            errors.append(f"{tool.name}: invalid lifecycle {tool.lifecycle!r}")
        if tool.lifecycle == "active" and not tool.handler:
            errors.append(f"{tool.name}: missing handler")
        elif tool.handler and known_handlers is not None and tool.handler not in known_handlers:
            errors.append(f"{tool.name}: unknown handler {tool.handler!r}")
        if tool.backend == "external" and not tool.binary:
            errors.append(f"{tool.name}: external provider requires a binary")
        unknown_strategies = sorted(set(tool.strategies) - valid_strategies)
        if unknown_strategies:
            errors.append(f"{tool.name}: unknown strategies {', '.join(unknown_strategies)}")
    return tuple(errors)


def recon_tool_status(tool: ReconTool) -> str:
    """Return disabled, unavailable, or ready without executing a backend."""
    if tool.lifecycle != "active":
        return tool.lifecycle
    if not is_recon_tool_enabled(tool.name):
        return "disabled"
    if tool.backend == "external" and (not tool.binary or not Pathfinder().locate(tool.name, executable=tool.binary).found):
        return "unavailable"
    return "ready"


def check_recon_tool(tool: ReconTool, *, timeout_seconds: float = 3.0) -> ReconToolCheck:
    """Probe an external provider's version command without contacting targets."""
    status = recon_tool_status(tool)
    if status != "ready":
        return ReconToolCheck(tool, status, detail=status)
    if tool.backend != "external":
        return ReconToolCheck(tool, "ready", version="built in", detail=f"{tool.backend} backend")
    resolution = Pathfinder().require(tool.name, executable=tool.binary, timeout_seconds=timeout_seconds)
    if not resolution.valid:
        status = "unavailable" if not resolution.found else "unhealthy"
        return ReconToolCheck(tool, status, version=resolution.version, detail=resolution.detail, path=resolution.path)
    return ReconToolCheck(tool, "ready", version=resolution.version, detail=resolution.detail, path=resolution.path)


def check_recon_tools(*, timeout_seconds: float = 3.0) -> tuple[ReconToolCheck, ...]:
    """Health-check every registered provider in deterministic registry order."""
    return tuple(check_recon_tool(tool, timeout_seconds=timeout_seconds) for tool in recon_tools())


def is_recon_tool_enabled(name: str) -> bool:
    """Return the user's persisted provider preference, defaulting to enabled."""
    return bool(_tool_preferences().get(name.strip().lower(), True))


def set_recon_tool_enabled(name: str, enabled: bool) -> bool:
    """Persist one provider preference; it takes effect in future pipeline plans."""
    tool = get_recon_tool(name)
    if tool is None:
        return False
    preferences = _tool_preferences()
    preferences[tool.name] = bool(enabled)
    path = _preferences_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(preferences, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
    return True


def _tool_preferences() -> dict[str, bool]:
    path = _preferences_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {str(name).lower(): bool(value) for name, value in raw.items()}


def _preferences_path() -> Path:
    root = Path(os.environ.get("BLACKLINE_DATA_DIR", Path.home() / ".blackline"))
    return root / "recon" / "tools.json"


def _words(value: object) -> tuple[str, ...]:
    return tuple(str(item).strip() for item in value if str(item).strip()) if isinstance(value, list) else ()


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


def _integer(value: object, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _positive_float(value: object) -> float | None:
    if value is None or value == "" or value == 0 or value == "0":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _ordered_providers(tools: Iterable[ReconTool]) -> tuple[ReconTool, ...]:
    return tuple(sorted(tools, key=lambda tool: (tool.priority, tool.name)))
