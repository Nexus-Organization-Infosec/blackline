import json
from datetime import datetime
from pathlib import Path
from utils.display import print_info, print_error, print_warning, print_success
from config.frontend.frontend_config import (
    get_utils_commands,
    get_tools,
    get_operators,
)


HISTORY_PATH = Path(__file__).resolve().parent.parent.parent / "history" / "history.jsonl"
HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)


def record_history(command, success: bool, on_exit: bool = False) -> None:
    """Record a command execution into history.jsonl"""
    if not command:
        return

    cmd_str = command.strip() if isinstance(command, str) else str(command.get("command", "")).strip()
    if not cmd_str:
        return

    main = cmd_str.split()[0].lower()

    skip_cmds = {"help", "clear", "version", "exit", "quit", "history", ""}
    if main in skip_cmds:
        return

    known = _get_known_commands()
    if main not in known:
        return

    entry = {
        "timestamp": datetime.now().isoformat(),
        "command": cmd_str,
        "success": bool(success),
    }

    try:
        with open(HISTORY_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print_warning(f"Failed to save history: {e}")


def _get_known_commands() -> set[str]:
    """Build a set of all known command keywords."""
    utils = [c.get("name", "").lower() for c in get_utils_commands()]
    tools = [k.lower() for k in get_tools().keys()]
    ops = [op.get("symbol", "").lower() for op in get_operators()]
    return set([n for n in utils + tools + ops if n])


def _load_history() -> list[dict]:
    if not HISTORY_PATH.exists():
        return []
    try:
        with open(HISTORY_PATH, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    except Exception as e:
        print_error(f"Failed to load history: {e}")
        return []


def handle_history(cfg: dict, arg: str):
    """Manage and inspect command history."""
    tokens = (arg or "").strip().split()
    subcmd = tokens[0] if tokens else "show"
    entries = _load_history()

    if subcmd == "clear":
        try:
            HISTORY_PATH.unlink(missing_ok=True)
            print_success("History cleared.")
        except Exception as e:
            print_error(f"Failed to clear history: {e}")
        return None

    if subcmd == "all":
        _print_entries(entries)
        return None

    if subcmd == "last" and len(tokens) > 1 and tokens[1].isdigit():
        n = int(tokens[1])
        _print_entries(entries[-n:], numbered=True)
        return None

    if subcmd == "restore" and len(tokens) > 1 and tokens[1].isdigit():
        idx = int(tokens[1])
        if 0 < idx <= len(entries):
            cmd_to_run = entries[-idx].get("command")
            return cmd_to_run
        print_warning("Invalid restore index.")
        return None

    _print_entries(entries[-5:], numbered=True)
    return None


def _print_entries(entries: list[dict], numbered: bool = False):
    if not entries:
        print_info("No history available.")
        return
    for i, e in enumerate(entries[::-1], 1):
        prefix = f"{i}. " if numbered else "- "
        print(f"{prefix}[{'✓' if e.get('success') else 'X'}] {e.get('command')} @ {e.get('timestamp')}")
