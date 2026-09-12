"""Declarative recon capability registry shared by CLI and planning layers."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from shutil import which

from blackline.config.tool_loader import get_recon_tool_registry_config
from blackline.utils.exec import run_command


@dataclass(frozen=True, slots=True)
class ReconTool:
    """One provider's capability and data-contract metadata."""

    name: str
    capability: str
    backend: str
    binary: str = ""
    produces: tuple[str, ...] = ()
    consumes: tuple[str, ...] = ()
    strategies: tuple[str, ...] = ()
    check_args: tuple[str, ...] = ()
    check_success_codes: tuple[int, ...] = (0,)


@dataclass(frozen=True, slots=True)
class ReconToolCheck:
    """Result of a bounded, non-network provider health probe."""

    tool: ReconTool
    status: str
    version: str = ""
    detail: str = ""


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
                binary=str(raw.get("binary", "")).strip(),
                produces=_words(raw.get("produces")),
                consumes=_words(raw.get("consumes")),
                strategies=_words(raw.get("strategies")),
                check_args=_words(raw.get("check_args")),
                check_success_codes=_integers(raw.get("check_success_codes"), default=(0,)),
            )
        )
    return tuple(tools)


def get_recon_tool(name: str) -> ReconTool | None:
    """Resolve one registered provider by its stable tool name."""
    normalized = name.strip().lower()
    return next((tool for tool in recon_tools() if tool.name == normalized), None)


def providers_for(product: str, *, strategy: str = "") -> tuple[ReconTool, ...]:
    """Find enabled providers capable of producing one normalized fact type."""
    return tuple(
        tool
        for tool in recon_tools()
        if product in tool.produces and is_recon_tool_enabled(tool.name) and (not strategy or strategy in tool.strategies)
    )


def recon_tool_status(tool: ReconTool) -> str:
    """Return disabled, unavailable, or ready without executing a backend."""
    if not is_recon_tool_enabled(tool.name):
        return "disabled"
    if tool.backend == "external" and (not tool.binary or which(tool.binary) is None):
        return "unavailable"
    return "ready"


def check_recon_tool(tool: ReconTool, *, timeout_seconds: float = 3.0) -> ReconToolCheck:
    """Probe an external provider's version command without contacting targets."""
    status = recon_tool_status(tool)
    if status != "ready":
        return ReconToolCheck(tool, status, detail=status)
    if tool.backend != "external":
        return ReconToolCheck(tool, "ready", version="built in", detail=f"{tool.backend} backend")
    if not tool.check_args:
        return ReconToolCheck(tool, "ready", version="available", detail="binary found")
    completed = run_command((tool.binary, *tool.check_args), timeout=timeout_seconds)
    output = (completed.stdout or completed.stderr or "").strip()
    version = next((line.strip() for line in output.splitlines() if line.strip()), "unknown")
    if completed.returncode not in tool.check_success_codes:
        return ReconToolCheck(tool, "unhealthy", version=version, detail=f"version probe exited {completed.returncode}")
    return ReconToolCheck(tool, "ready", version=version[:120], detail="version probe succeeded")


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
