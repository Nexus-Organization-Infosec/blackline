"""Tab completion helpers."""

from __future__ import annotations

import re
import sys

try:
    import readline
except ImportError:  # pragma: no cover - readline is Unix-only.
    readline = None  # type: ignore[assignment]

from blackline.config.tool_loader import get_tool_config
from blackline.cli.commands.system.help_cmd import load_help_groups, load_operators
from blackline.cli.commands.system.jobs_cmd import list_jobs

STATIC_COMMANDS = ("quit",)
COMMAND_SEPARATORS = ("&", "|", ">", "+", "?", "||", "//")
_REPORTED_UI_ERRORS: set[str] = set()


def known_command_names() -> set[str]:
    """Return known commands as a set for validation/highlighting."""
    return set(command_names())


def command_names() -> tuple[str, ...]:
    """Return command names loaded from JSON configuration."""
    names = set(STATIC_COMMANDS)
    for group in _safe_help_groups():
        for item in group.items:
            names.add(item.name)
    return tuple(sorted(names))


def help_topics() -> tuple[str, ...]:
    """Return help topics loaded from JSON configuration."""
    topics = {"operators"}
    for group in _safe_help_groups():
        topics.add(group.id)
        topics.add(group.title.lower())
        for item in group.items:
            topics.add(item.name)
    return tuple(sorted(topics))


def operator_symbols() -> tuple[str, ...]:
    """Return operator symbols loaded from JSON configuration."""
    return tuple(operator.get("symbol", "") for operator in _safe_operators() if operator.get("symbol"))


def complete_text(text: str) -> list[str]:
    """Return completions for the current shell input."""
    return [f"{completion} " for completion in completion_replacements(text)]


def completion_replacements(text: str) -> list[str]:
    """Return context-aware completion replacements for the current word."""
    return [replacement for replacement, _ in completion_items(text)]


def completion_items(text: str) -> list[tuple[str, str]]:
    """Return context-aware completion replacements and display metadata."""
    leading = text.lstrip()
    if not leading:
        return [(name, "command") for name in command_names()]

    if is_bracket_command(leading):
        return bracket_command_items(leading)

    if " " not in leading:
        return [(name, "command") for name in command_names() if name.startswith(leading.lower())]

    if expects_command(leading):
        token = "" if leading.endswith((" ", "\t")) else leading.rsplit(maxsplit=1)[-1]
        return [(name, "command") for name in command_names() if name.startswith(token.lower())]

    if leading.startswith("delete "):
        return delete_target_items(leading)

    if leading.startswith("enter "):
        return enter_target_items(leading)

    if leading.startswith("show "):
        return show_target_items(leading)

    if leading.startswith("help "):
        topic_prefix = leading.removeprefix("help ").strip().lower()
        return [(topic, "help") for topic in help_topics() if topic.startswith(topic_prefix)]

    token = leading.rsplit(maxsplit=1)[-1]
    return [(symbol, "operator") for symbol in operator_symbols() if symbol.startswith(token)]


def delete_target_replacements(text: str) -> list[str]:
    """Return existing job ids for delete completion."""
    return [replacement for replacement, _ in delete_target_items(text)]


def enter_target_replacements(text: str) -> list[str]:
    """Return existing job ids for enter completion."""
    return [replacement for replacement, _ in enter_target_items(text)]


def show_target_replacements(text: str) -> list[str]:
    """Return existing job ids for show completion."""
    return [replacement for replacement, _ in show_target_items(text)]


def delete_target_items(text: str) -> list[tuple[str, str]]:
    """Return existing job ids and metadata for delete completion."""
    remainder = text.removeprefix("delete ")
    current = remainder.rsplit(",", 1)[-1].strip()
    used = {normalize_completion_job_id(part) for part in remainder.split(",")[:-1]}
    options = [("*", "all jobs")]
    options.extend((f"#{job.id}", f"{job.module} {job.status}") for job in list_jobs())
    return [
        (option, meta)
        for option, meta in options
        if option.startswith(current.upper()) and normalize_completion_job_id(option) not in used
    ]


def enter_target_items(text: str) -> list[tuple[str, str]]:
    """Return existing job ids and metadata for enter completion."""
    current = text.removeprefix("enter ").strip().upper()
    return [
        (f"#{job.id}", f"{job.module} {job.status}")
        for job in list_jobs()
        if f"#{job.id}".startswith(current)
    ]


def show_target_items(text: str) -> list[tuple[str, str]]:
    """Return existing job ids and metadata for show completion."""
    current = text.removeprefix("show ").strip().upper()
    return [
        (f"#{job.id}", f"{job.module} {job.status}")
        for job in list_jobs()
        if f"#{job.id}".startswith(current)
    ]


def current_completion_length(text: str, word: str) -> int:
    """Return how many chars prompt-toolkit should replace for current context."""
    leading = text.lstrip()
    if is_bracket_command(leading):
        token = bracket_token(leading)
        if "=" in token:
            return len(token.split("=", 1)[1].strip())
        return len(token)
    if leading.startswith("delete "):
        remainder = leading.removeprefix("delete ")
        return len(remainder.rsplit(",", 1)[-1].lstrip())
    if leading.startswith("enter "):
        return len(leading.removeprefix("enter ").lstrip())
    if leading.startswith("show "):
        return len(leading.removeprefix("show ").lstrip())
    return len(word)


def next_suggestions(text: str) -> list[str]:
    """Return display-friendly suggestions for what can be typed next."""
    suggestions = complete_text(text)
    if suggestions:
        return [suggestion.strip() for suggestion in suggestions]
    if not text.strip() or expects_command(text):
        return list(command_names())
    return list(operator_symbols())


def expects_command(text: str) -> bool:
    """Return True when the cursor appears to be at a command position."""
    stripped = text.rstrip()
    if not stripped:
        return True
    tokens = stripped.split()
    return bool(tokens and tokens[-1] in set(operator_symbols()))


def command_spans(text: str) -> list[tuple[int, int, bool]]:
    """Return command-token spans with validity for live highlighting."""
    spans: list[tuple[int, int, bool]] = []
    known = known_command_names()
    operators = set(operator_symbols()) | set(COMMAND_SEPARATORS)
    expecting_command = True

    for match in re.finditer(r"\S+", text):
        token = match.group(0)
        if token in operators:
            expecting_command = True
            continue

        if expecting_command:
            command = token.split("[", 1)[0].lower()
            end = match.start() + len(command)
            spans.append((match.start(), end, command in known))
            expecting_command = False

    return spans


class ReadlineCompleter:
    """Readline-compatible completer backed by JSON configuration."""

    def __init__(self) -> None:
        self.matches: list[str] = []

    def complete(self, text: str, state: int) -> str | None:
        if state == 0:
            line = current_line_buffer(text)
            self.matches = _readline_matches(line, text)
        try:
            return self.matches[state]
        except IndexError:
            return None


def _readline_matches(line: str, text: str) -> list[str]:
    suggestions = complete_text(line)
    leading = line.lstrip()
    if leading.startswith("help "):
        return [suggestion.removeprefix("help ") for suggestion in suggestions]
    if not text and leading:
        return []
    return suggestions


def current_line_buffer(fallback: str) -> str:
    """Return the active readline buffer when readline is available."""
    if readline is None:
        return fallback
    return readline.get_line_buffer() or fallback


def normalize_completion_job_id(identifier: str) -> str:
    """Normalize job id strings used by completion."""
    return identifier.strip().upper().removeprefix("#")


def is_bracket_command(text: str) -> bool:
    """Return True when text is inside a module[...] expression."""
    return "[" in text and not text.rstrip().endswith("]")


def bracket_command_items(text: str) -> list[tuple[str, str]]:
    """Return completion items for module[...] expressions."""
    module, inner = split_bracket_command(text)
    if module != "recon":
        return []

    arguments = recon_argument_config()
    used_keys = {key for key, _ in parse_bracket_pairs(inner)}
    token = bracket_token(text)
    if "=" in token:
        key, value_prefix = token.split("=", 1)
        choices = argument_choices(arguments, key.strip())
        return [
            (choice + bracket_suffix(inner), argument_description(arguments, key.strip()))
            for choice in choices
            if choice.lower().startswith(value_prefix.lower())
        ]

    key_prefix = token.strip().lower()
    items: list[tuple[str, str]] = []
    for key, details in arguments.items():
        if key in used_keys:
            continue
        if key.startswith(key_prefix):
            items.append((f"{key}=", str(details.get("description", ""))))
    return items


def split_bracket_command(text: str) -> tuple[str, str]:
    """Split module[inner into module name and inner token text."""
    module, inner = text.split("[", 1)
    return module.strip().lower(), inner


def parse_bracket_pairs(inner: str) -> list[tuple[str, str]]:
    """Parse already-entered key=value pairs."""
    pairs: list[tuple[str, str]] = []
    for chunk in inner.split(","):
        if "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        pairs.append((key.strip().lower(), value.strip()))
    return pairs


def bracket_token(text: str) -> str:
    """Return the currently edited token inside brackets."""
    _, inner = split_bracket_command(text)
    return inner.rsplit(",", 1)[-1].strip()


def bracket_suffix(inner: str) -> str:
    """Return the suffix appended after a completed value suggestion."""
    open_brackets = inner.count("[")
    return ", " if open_brackets >= 0 else ""


def recon_argument_config() -> dict[str, dict]:
    """Return recon argument metadata from config."""
    try:
        config = get_tool_config("recon")
    except Exception as exc:
        _report_ui_error(f"tool config unavailable: {exc}")
        return {}
    arguments = config.get("arguments", {})
    return arguments if isinstance(arguments, dict) else {}


def argument_choices(arguments: dict[str, dict], key: str) -> list[str]:
    """Return configured choices for one argument."""
    details = arguments.get(key, {})
    choices = details.get("choices", []) if isinstance(details, dict) else []
    return [str(choice) for choice in choices]


def argument_description(arguments: dict[str, dict], key: str) -> str:
    """Return configured description for one argument."""
    details = arguments.get(key, {})
    if not isinstance(details, dict):
        return ""
    return str(details.get("description", ""))


def _safe_help_groups():
    try:
        return load_help_groups()
    except Exception as exc:
        _report_ui_error(f"command config unavailable: {exc}")
        return ()


def _safe_operators():
    try:
        return load_operators()
    except Exception as exc:
        _report_ui_error(f"operator config unavailable: {exc}")
        return ()


def _report_ui_error(message: str) -> None:
    if message in _REPORTED_UI_ERRORS:
        return
    _REPORTED_UI_ERRORS.add(message)
    sys.__stderr__.write(f"\n[error] {message}\n")
    sys.__stderr__.flush()
