"""Configuration-backed help command."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from blackline import __version__
from blackline.cli.ui.display import write_line, write_segments

MIN_RULE_WIDTH = 40


@dataclass(frozen=True, slots=True)
class HelpItem:
    """One command help entry loaded from configuration."""

    name: str
    description: str
    usage: str = ""
    long_description: str = ""
    arguments: tuple[tuple[str, str], ...] = ()
    examples: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class HelpGroup:
    """One command group loaded from configuration."""

    id: str
    title: str
    items: tuple[HelpItem, ...]


def handle_help(topic: str = "", *, use_color: bool | None = None) -> bool:
    """Render main, category, or command-specific help."""
    topic = topic.strip().lower()
    groups = load_help_groups()
    operators = load_operators()

    if not topic:
        render_main_help(groups, operators, use_color=use_color)
        return True

    if topic == "operators":
        render_operators_help(operators, use_color=use_color)
        return True

    group = find_group(groups, topic)
    if group:
        render_group_help(group, use_color=use_color)
        return True

    item = find_item(groups, topic)
    if item:
        render_item_help(item, use_color=use_color)
        return True

    write_line(f"no help found for '{topic}'", color="red", use_color=use_color)
    return False


def load_help_groups(config_root: Path | None = None) -> tuple[HelpGroup, ...]:
    """Load configured command groups."""
    config_root = config_root or _config_root()
    raw = _load_json(config_root / "commands.json")
    return tuple(_group_from_dict(group) for group in raw.get("groups", []))


def load_operators(config_root: Path | None = None) -> tuple[dict[str, str], ...]:
    """Load configured operators."""
    config_root = config_root or _config_root()
    raw = _load_json(config_root / "operators.json")
    return tuple(raw.get("items", []))


def render_main_help(
    groups: tuple[HelpGroup, ...],
    operators: tuple[dict[str, str], ...],
    *,
    width: int | None = None,
    use_color: bool | None = None,
) -> None:
    """Render the top-level help page."""
    rule = _terminal_rule(width)
    write_line(f"blackline v{_short_version(__version__)}", use_color=use_color)
    write_line(rule, color="muted", use_color=use_color)

    for group in groups:
        write_line()
        _section_title(group.title, use_color=use_color)
        _section_rule(group.title, use_color=use_color)
        _command_rows([(item.name, item.description) for item in group.items], use_color=use_color)

    write_line()
    _section_title("OPERATORS", use_color=use_color)
    _section_rule("OPERATORS", use_color=use_color)
    _operator_rows(operators, use_color=use_color)

    write_line()
    write_line(rule, color="muted", use_color=use_color)
    write_line("type 'help <command>' for details", color="muted", use_color=use_color)


def render_group_help(group: HelpGroup, *, use_color: bool | None = None) -> None:
    """Render one configured command group."""
    _section_title(group.title, use_color=use_color)
    _section_rule(group.title, use_color=use_color)
    _command_rows([(item.name, item.description) for item in group.items], use_color=use_color)


def render_operators_help(operators: tuple[dict[str, str], ...], *, use_color: bool | None = None) -> None:
    """Render configured operators."""
    _section_title("OPERATORS", use_color=use_color)
    _section_rule("OPERATORS", use_color=use_color)
    _operator_rows(operators, use_color=use_color)


def render_item_help(item: HelpItem, *, use_color: bool | None = None) -> None:
    """Render command-specific help."""
    write_line(f"[{item.name}]", color="cyan", use_color=use_color)
    write_line()
    _detail_section("description", [item.long_description or item.description], use_color=use_color)

    if item.usage:
        write_line()
        _detail_section("usage", [item.usage], use_color=use_color)

    if item.arguments:
        write_line()
        _section_title("arguments", use_color=use_color)
        _section_rule("arguments", use_color=use_color)
        _command_rows(list(item.arguments), min_width=8, use_color=use_color)

    if item.examples:
        write_line()
        _detail_section("examples", list(item.examples), use_color=use_color)


def find_group(groups: tuple[HelpGroup, ...], topic: str) -> HelpGroup | None:
    """Find a configured group by id or title."""
    for group in groups:
        if topic in {group.id.lower(), group.title.lower()}:
            return group
    return None


def find_item(groups: tuple[HelpGroup, ...], topic: str) -> HelpItem | None:
    """Find a configured command by name."""
    for group in groups:
        for item in group.items:
            if item.name.lower() == topic:
                return item
    return None


def _command_rows(rows: list[tuple[str, str]], *, min_width: int = 9, use_color: bool | None) -> None:
    if not rows:
        return

    width = max(min_width, *(len(name) for name, _ in rows))
    for name, description in rows:
        write_segments(
            [
                (name.ljust(width), "white"),
                ("  ", "muted"),
                (description, "muted"),
            ],
            use_color=use_color,
        )


def _operator_rows(operators: tuple[dict[str, str], ...], *, use_color: bool | None) -> None:
    if not operators:
        return

    symbol_width = max(len(operator.get("symbol", "")) for operator in operators)
    name_width = max(len(operator.get("name", "")) for operator in operators)
    for operator in operators:
        symbol = operator.get("symbol", "")
        name = operator.get("name", "")
        description = operator.get("description", "")
        write_segments(
            [
                (symbol.ljust(symbol_width), "yellow"),
                ("  ", "muted"),
                (name.ljust(name_width), "white"),
                ("  ", "muted"),
                (description, "muted"),
            ],
            use_color=use_color,
        )


def _detail_section(title: str, lines: list[str], *, use_color: bool | None) -> None:
    _section_title(title, use_color=use_color)
    _section_rule(title, use_color=use_color)
    for line in lines:
        write_line(line, use_color=use_color)


def _section_title(title: str, *, use_color: bool | None) -> None:
    write_line(title, color="cyan", use_color=use_color)


def _section_rule(title: str, *, use_color: bool | None) -> None:
    write_line("─" * len(title), color="muted", use_color=use_color)


def _terminal_rule(width: int | None = None) -> str:
    if width is None:
        width = shutil.get_terminal_size((MIN_RULE_WIDTH, 20)).columns
    return "─" * max(MIN_RULE_WIDTH, width)


def _group_from_dict(raw: dict[str, Any]) -> HelpGroup:
    return HelpGroup(
        id=str(raw.get("id", "")),
        title=str(raw.get("title", "")),
        items=tuple(_item_from_dict(item) for item in raw.get("items", [])),
    )


def _item_from_dict(raw: dict[str, Any]) -> HelpItem:
    return HelpItem(
        name=str(raw.get("name", "")),
        description=str(raw.get("description", "")),
        usage=str(raw.get("usage", "")),
        long_description=str(raw.get("long_description", "")),
        arguments=tuple((str(key), str(value)) for key, value in raw.get("arguments", [])),
        examples=tuple(str(example) for example in raw.get("examples", [])),
    )


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        return {}
    return data


def _config_root() -> Path:
    return Path(__file__).resolve().parents[3] / "config"


def _short_version(version: str) -> str:
    parts = version.split(".")
    if len(parts) >= 2:
        return ".".join(parts[:2])
    return version
