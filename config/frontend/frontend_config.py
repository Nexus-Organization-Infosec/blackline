# blackline/config/frontend/frontend_config.py 

import os
import json
import uuid
from typing import Any, Dict, List, Optional

from config.config_loader import load_config


_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

_UTILS_PATH = "frontend/utils_commands.json"
_OPERATORS_PATH = "frontend/operators.json"
_TOOLS_PATH = "frontend/tool_args.json"

_BLINE_DB_FILENAME = os.path.join(_BASE_DIR, "bline_db.json")


_UTILS: Optional[Dict[str, Any]] = None
_OPERATORS: Optional[Dict[str, Any]] = None
_TOOLS: Optional[Dict[str, Any]] = None


def _ensure_bline_db_exists():
    """Ensure the bline_db.json exists and has a list."""
    if not os.path.exists(_BLINE_DB_FILENAME):
        with open(_BLINE_DB_FILENAME, "w", encoding="utf-8") as f:
            json.dump({"entries": []}, f, indent=2)


def reload_utils() -> Dict[str, Any]:
    global _UTILS
    _UTILS = load_config(_UTILS_PATH) or {}
    return _UTILS


def reload_operators() -> Dict[str, Any]:
    global _OPERATORS
    _OPERATORS = load_config(_OPERATORS_PATH) or {}
    return _OPERATORS


def reload_tools() -> Dict[str, Any]:
    global _TOOLS
    _TOOLS = load_config(_TOOLS_PATH) or {}
    return _TOOLS


def reload_all() -> None:
    """Reload all configuration files and ensure DB exists."""
    reload_utils()
    reload_operators()
    reload_tools()
    _ensure_bline_db_exists()

def _get_utils() -> Dict[str, Any]:
    global _UTILS
    if _UTILS is None:
        _UTILS = load_config(_UTILS_PATH) or {}
    return _UTILS


def _get_operators() -> Dict[str, Any]:
    global _OPERATORS
    if _OPERATORS is None:
        _OPERATORS = load_config(_OPERATORS_PATH) or {}
    return _OPERATORS


def _get_tools() -> Dict[str, Any]:
    global _TOOLS
    if _TOOLS is None:
        _TOOLS = load_config(_TOOLS_PATH) or {}
    return _TOOLS

def get_utils_commands() -> List[Dict[str, Any]]:
    """Return list of all utility (shell-level) commands."""
    utils = _get_utils()
    return utils.get("commands", []) if isinstance(utils, dict) else []


def get_operators() -> List[Dict[str, Any]]:
    """Return list of operator definitions (&, &&, ->, etc.)."""
    ops = _get_operators()
    return ops.get("operators", []) if isinstance(ops, dict) else []

def get_operator_symbols() -> List[str]:
    ops = get_operators()
    symbols = [
        op.get("symbol")
        for op in ops
        if isinstance(op, dict) and "symbol" in op
    ]
    return sorted(symbols, key=len, reverse=True)

def get_tools() -> Dict[str, Any]:
    """Return dictionary of all tool definitions (recon, exploit, etc.)."""
    return _get_tools().get("tools", {}) if isinstance(_get_tools(), dict) else {}


def get_all_frontend_config() -> Dict[str, Any]:
    """Return combined view of utils, operators, and tools."""
    return {
        "utils": get_utils_commands(),
        "operators": get_operators(),
        "tools": get_tools()
    }

def _read_bline_db() -> Dict[str, Any]:
    _ensure_bline_db_exists()
    with open(_BLINE_DB_FILENAME, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_bline_db(data: Dict[str, Any]) -> None:
    with open(_BLINE_DB_FILENAME, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def list_bline_entries() -> List[Dict[str, Any]]:
    """Return list of .bline entries from the DB."""
    db = _read_bline_db()
    return db.get("entries", [])


def import_bline_from_path(path: str, name: Optional[str] = None) -> Dict[str, Any]:
    """Import a .bline file into the local DB."""
    if not os.path.exists(path):
        raise FileNotFoundError(f".bline file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    entry = {
        "id": str(uuid.uuid4()),
        "name": name or os.path.basename(path),
        "path": os.path.abspath(path),
        "content": content
    }

    db = _read_bline_db()
    entries = db.get("entries", [])
    entries.append(entry)
    db["entries"] = entries
    _write_bline_db(db)
    return entry


def delete_bline_entry_by_index(index: int) -> bool:
    """Delete an entry by its 1-based index."""
    db = _read_bline_db()
    entries = db.get("entries", [])
    if index < 1 or index > len(entries):
        return False
    entries.pop(index - 1)
    db["entries"] = entries
    _write_bline_db(db)
    return True


def get_bline_entry_by_index(index: int) -> Optional[Dict[str, Any]]:
    entries = list_bline_entries()
    if index < 1 or index > len(entries):
        return None
    return entries[index - 1]

def init_frontend_config():
    """Ensure configs and DB are present at shell startup."""
    reload_all()


def help_for(cmd_name: str) -> str:
    """Generate help text for a utility or tool command."""
    for cmd in get_utils_commands():
        if cmd_name == cmd.get("name") or cmd_name in cmd.get("aliases", []):
            desc = cmd.get("description", "No description.")
            examples = cmd.get("syntax_examples", [])
            out = desc
            if examples:
                out += "\n\nExamples:\n  " + "\n  ".join(examples)
            return out

    tools = get_tools()
    if cmd_name in tools:
        t = tools[cmd_name]
        desc = t.get("description", "No description.")
        examples = t.get("syntax_examples", [])
        out = desc
        if examples:
            out += "\n\nExamples:\n  " + "\n  ".join(examples)
        return out

    return f"No help found for '{cmd_name}'."
