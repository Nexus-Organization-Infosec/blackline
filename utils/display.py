# utils/display.py 

import shutil 
import os 
import textwrap
from .colors import color 

def get_terminal_size(default_width: int = 80, default_height: int = 24) -> tuple[int, int]:
    """Returns the current terminal (width, height). Falls back to defaults if unavailable."""
    try:
        size = shutil.get_terminal_size()
        return size.columns, size.lines
    except Exception:
        return default_width, default_height

def get_terminal_width(default: int = 80) -> int:
    """Convenience function returning only terminal width."""
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


def draw_line(
    char: str = "-",
    color_name: str = "white",
    bold: bool = False,
    width: int | None = None,
    margin: int = 0,
    return_str: bool = False
) -> str | None:
    """Draw characters based on the width of the terminal"""
    term_width = get_terminal_width()
    usable = width or term_width
    usable = max(10, usable - margin * 2)
    line = color(char * usable, color_name, bold=bold)
    if return_str:
        return line
    print(line)

def indent_wrap(
    text: str,
    indent: int = 2,
    width: int | None = None,
    prefix: str | None = None,
    prefix_color: str = "white",
    text_color: str = "white",
    bold_prefix: bool = True,
    bold_text: bool = False,
    pad_prefix: bool = True,
) -> list[str]:
    text = str(text or "").replace("\t", "    ")
    width = width or get_terminal_width()
    indent_str = " " * indent
    prefix = str(prefix or "")

    # compute effective wrap width
    prefix_space = (len(prefix) + (1 if pad_prefix else 0)) if prefix else 0
    wrap_width = max(20, width - indent - prefix_space)

    wrapped_lines = textwrap.wrap(text, width=wrap_width) or [""]

    lines = []
    for i, line in enumerate(wrapped_lines):
        if prefix and i == 0:
            lines.append(
                f"{indent_str}"
                f"{color(prefix + (' ' if pad_prefix else ''), prefix_color, bold=bold_prefix)}"
                f"{color(line, text_color, bold=bold_text)}"
            )
        elif prefix:
            # continuation line with prefix spacing only
            lines.append(
                f"{indent_str}{' ' * prefix_space}{color(line, text_color, bold=bold_text)}"
            )
        else:
            # no prefix case
            lines.append(f"{indent_str}{color(line, text_color, bold=bold_text)}")

    return lines



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