from __future__ import annotations

from prompt_toolkit.completion import Completer, Completion
from config.config_loader import load_config


class BlacklineCompleter(Completer):
    """JSON driven completer for Blackline."""

    def __init__(self):
        cfg = load_config("frontend/commands.json")
        self.commands = cfg.get("commands", {})
        self.actions = cfg.get("actions", {})

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        stripped = text.lstrip()
        ends_space = stripped.endswith(" ")

        if "[" in stripped:
            yield from self._complete_action_dsl(stripped)
            return

        parts = stripped.split()

        if not parts:
            yield from self._complete_top_level("")
            return

        if len(parts) == 1 and not ends_space:
            yield from self._complete_top_level(parts[0])
            return

        head = parts[0]
        tail = "" if ends_space else parts[-1]

        if head in self.commands:
            yield from self._complete_command(head, tail)
            return

    def _complete_top_level(self, prefix: str):
        for name in sorted(self.commands.keys() | self.actions.keys()):
            if name.startswith(prefix):
                yield Completion(name, start_position=-len(prefix))

    def _complete_command(self, cmd: str, current: str):
        spec = self.commands.get(cmd, {})
        start_pos = -len(current)

        subs = spec.get("subcommands", {})
        for name in subs:
            if name.startswith(current):
                yield Completion(name, start_position=start_pos)

        args = spec.get("args", [])
        for arg in args:
            if arg.startswith(current):
                yield Completion(arg, start_position=start_pos)

    def _complete_action_dsl(self, text: str):
        action, _, rest = text.partition("[")
        action = action.strip()

        if action not in self.actions:
            return

        keys = self.actions[action].get("keys", {})

        inside = rest.rstrip("]")
        parts = inside.split(",")

        current = parts[-1].strip()
        start_pos = -len(current)

        if "=" not in current:
            for key in keys:
                if key.startswith(current):
                    yield Completion(key + "=", start_position=start_pos)
            return

        key, _, value = current.partition("=")
        key = key.strip()
        value = value.strip()

        key_spec = keys.get(key)
        if not key_spec:
            return

        values = key_spec.get("values")
        if values:
            for v in values:
                if v.startswith(value):
                    yield Completion(v, start_position=-len(value))
