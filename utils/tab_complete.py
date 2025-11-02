import shlex
import time
import difflib
from config.frontend.frontend_config import (
    get_utils_commands,
    get_tools,
    get_operators,
)

last_tab_state = {
    "last_line": "",
    "last_time": 0,
    "tab_count": 0,
}

def _get_builtin_cmds():
    """Return all known command, tool, and operator names."""
    utils = [c.get("name") for c in get_utils_commands()]
    tools = list(get_tools().keys())
    ops = [c.get("symbol") for c in get_operators()]
    return utils + tools + ops


def _get_subcommands():
    """Return subcommand mapping (tools, utils, etc.)."""
    sub = {}
    sub.update({name: list(t.keys()) if isinstance(t, dict) else [] for name, t in get_tools().items()})
    sub["history"] = ["all", "find", "clear", "on", "off"]
    sub["help"] = _get_builtin_cmds()
    return sub


def _complete_subcommand(cmd_name: str, text: str, line: str):
    """Handle nested subcommand completions for any command."""
    tokens = shlex.split(line)
    if not tokens or tokens[0] != cmd_name:
        return []

    submap = _get_subcommands().get(cmd_name, [])
    idx = 1

    while idx < len(tokens) and submap:
        tok = tokens[idx]
        if isinstance(submap, dict):
            if tok in submap:
                submap = submap[tok]
                idx += 1
            else:
                return [s for s in submap.keys() if s.lower().startswith(tok.lower())]
        elif isinstance(submap, list):
            if idx == len(tokens) - 1 and not line.endswith(" "):
                return [s for s in submap if s.lower().startswith(tok.lower())]
            else:
                if tok in submap:
                    return []
                return [s for s in submap if s.lower().startswith(tok.lower())]
        else:
            break

    if isinstance(submap, dict):
        return [s for s in submap.keys() if s.lower().startswith(text.lower())]
    if isinstance(submap, list):
        return [s for s in submap if s.lower().startswith(text.lower())]
    return []

def complete_help(text, *_):
    """Autocomplete for `help` command."""
    return [x for x in _get_builtin_cmds() if x.lower().startswith(text.lower())]


def complete_history(text, line, *_):
    """Autocomplete for `history` command."""
    return _complete_subcommand("history", text, line)


def complete_run(text, line, *_):
    """Possible completer for run command (if used)."""
    return []


def complete_load(text, line, *_):
    """Completer for load command."""
    return []


def complete_tools(text, line, *_):
    """Autocomplete for tools like recon, exploit, etc."""
    tokens = shlex.split(line)
    if not tokens:
        return []
    cmd = tokens[0]
    if cmd in get_tools():
        tool = get_tools()[cmd]
        sub = tool.get("phases") if isinstance(tool, dict) else None
        if sub and isinstance(sub, list):
            return [s for s in sub if s.lower().startswith(text.lower())]
    return []


def complete_command(text, line, begidx, endidx):
    """Generic fallback completion for any unknown command."""
    all_cmds = _get_builtin_cmds()
    return [cmd for cmd in all_cmds if cmd.lower().startswith(text.lower())]
