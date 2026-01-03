import json
from datetime import datetime, date
from pathlib import Path

from prompt_toolkit.history import FileHistory

from utils.display import (
    print_info,
    print_error,
    print_warning,
    print_success,
)

from config.frontend.frontend_config import (
    get_utils_commands,
    get_tools,
    get_operators,
)


class History:
    def __init__(self, base_dir: Path | None = None):
        self.base_dir = (
            base_dir
            or Path(__file__).resolve().parent.parent / "history"
        )
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def input_history(self) -> FileHistory:
        """History used by prompt_toolkit for up-arrow editing."""
        return FileHistory(str(self.base_dir / "history.txt"))

    def record(self, command: str, success: bool) -> None:
        """Record an executed command into daily JSONL history."""
        if not command:
            return

        cmd = command.strip()
        if not cmd:
            return

        main = cmd.split()[0].lower()
        if main in {"help", "clear", "version", "exit", "quit", "history"}:
            return

        if main not in self._known_commands():
            return

        entry = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "command": cmd,
            "success": bool(success),
        }

        try:
            with open(self._today_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            print_warning(f"Failed to write history: {e}")

    def handle(self, arg: str):
        """
        history
        history N
        history last N
        history all
        history restore N
        history clear
        """
        tokens = (arg or "").strip().split()

        entries = self._load_all()
        total = len(entries)

        if not tokens:
            if not entries:
                print_info("No history available.")
                return None
            start = max(0, total - 5)
            self._print(entries[start:], start_index=start + 1)
            return None

        sub = tokens[0]

        if sub == "clear":
            self._clear()
            return None

        if not entries:
            print_info("No history available.")
            return None

        if sub == "all":
            self._print(entries, start_index=1)
            return None

        if sub == "last" and len(tokens) > 1 and tokens[1].isdigit():
            n = int(tokens[1])
            start = max(0, total - n)
            self._print(entries[start:], start_index=start + 1)
            return None

        if sub.isdigit():
            n = int(sub)
            start = max(0, total - n)
            self._print(entries[start:], start_index=start + 1)
            return None
    
        if sub == "restore" and len(tokens) > 1 and tokens[1].isdigit():
            idx = int(tokens[1])
            if 1 <= idx <= total:
                return entries[idx - 1]["command"]
            print_warning("Invalid restore index.")
            return None

        print_warning("Invalid history command.")
        return None

    def _today_path(self) -> Path:
        return self.base_dir / f"{date.today().isoformat()}.jsonl"

    def _load_all(self) -> list[dict]:
        """Load all history entries in chronological order"""
        entries: list[dict] = []
        for file in sorted(self.base_dir.glob("*.jsonl")):
            try:
                with open(file, "r", encoding="utf-8") as f:
                    entries.extend(json.loads(l) for l in f if l.strip())
            except Exception as e:
                print_error(f"Failed to read history file {file.name}: {e}")
        return entries

    def _clear(self):
        """Clear ALL history artifacts."""
        deleted = []
        truncated = []
        failed = []

        for f in self.base_dir.iterdir():
            if not f.is_file():
                continue
            try:
                if f.suffix == ".jsonl":
                    f.unlink()
                    deleted.append(f.name)
                else:
                    f.write_text("", encoding="utf-8")
                    truncated.append(f.name)
            except Exception as e:
                failed.append((f.name, str(e)))

        if deleted or truncated:
            parts = []
            if deleted:
                parts.append(f"deleted: {', '.join(deleted)}")
            if truncated:
                parts.append(f"cleared: {', '.join(truncated)}")
            print_success("History cleared.")
        else:
            print_success("History already empty.")

        for name, err in failed:
            print_error(f"Failed to clear {name}: {err}")

    def _print(self, entries: list[dict], start_index: int):
        """Print entries in chronological order with absolute numbering."""
        for offset, e in enumerate(entries):
            idx = start_index + offset
            mark = "✓" if e.get("success") else "✗"
            print_info(f"{idx}. [{mark}] {e['command']} @ {e['timestamp']}")

    def _known_commands(self) -> set[str]:
        utils = [c.get("name", "").lower() for c in get_utils_commands()]
        tools = [k.lower() for k in get_tools().keys()]
        ops = [op.get("symbol", "").lower() for op in get_operators()]
        return {x for x in utils + tools + ops if x}