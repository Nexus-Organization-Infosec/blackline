# utils/display.py 

import shutil 
import os 
from .colors import color 

def get_terminal_size(default_width: int = 80, default_height: int = 24) -> tuple[int, int]:
    """
    Returns the current terminal (width, height). Falls back to defaults if unavailable.
    """
    try:
        size = shutil.get_terminal_size()
        return size.columns, size.lines
    except Exception:
        return default_width, default_height

def get_terminal_width(default: int = 80) -> int:
    """
    Convenience function returning only terminal width.
    """
    width, _ = get_terminal_size(default, 24)
    return width

def print_kv_table(data: dict, title: str = None):
    """Display key-value pairs in an aligned table."""
    if not data:
        return

    if title:
        print("\n" + color(title, "yellow", bold=True))
        print("-" * len(title))

    max_key_len = max(len(k) for k in data)
    for k, v in data.items():
        val_lines = str(v).splitlines() or [""]
        print(f"  {k.ljust(max_key_len)} : {val_lines[0]}")
        for line in val_lines[1:]:
            print(" " * (max_key_len + 4) + line)
    print()


def print_boxed_summary(title: str, items: list[tuple[str, str]]):
    """Prints a box-style summary that adapts to terminal width."""
    if not items:
        return

    width = get_terminal_width()
    max_line_len = max(len(f"{label} : {value}") for label, value in items)
    content_width = min(width - 6, max_line_len + 2)

    print("\n+" + "=" * content_width + "+")
    print("| " + color(title.ljust(content_width - 1), "cyan", bold=True) + "|")
    print("+" + "-" * content_width + "+")

    for label, value in items:
        line = f"{label} : {value}"
        if len(line) > content_width - 1:
            line = line[:content_width - 4] + "..."
        print(f"| {line.ljust(content_width - 1)}|")

    print("+" + "-" * content_width + "+\n")


def print_list(title: str, items: list[str], bullet: str = "-", sort=False, dedup=False):
    """Prints a titled bulleted list."""
    if not items:
        return

    if dedup:
        items = list(set(items))
    if sort:
        items = sorted(items)

    if title:
        print("\n" + color(title, "cyan", bold=True))
        print("-" * len(title))

    for item in items:
        print(f"  {bullet} {item}")
    print()

def print_warning(msg: str):
    print(color(f"[!] {msg}", "yellow", bold=True))

def print_success(msg: str):
    print(color(f"[✓] {msg}", "green"))

def print_info(msg: str):
    print(color(f"[*] {msg}", "cyan"))

def print_step(msg: str):
    print(color(f"[+] {msg}", "blue"))

def print_error(msg: str):
    print(color(f"[✗] {msg}", "red", bold=True))