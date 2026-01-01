import textwrap

from config.frontend.frontend_config import (
    get_utils_commands,
    get_tools,
    get_operators,
)

from utils.display import (
    print_info,
    print_error,
    get_terminal_width,
    indent_wrap,
    draw_line,
)

from utils.colors import color

from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import ANSI


ARROW = "→"


def _format_usage(cmd_name: str, cmd: dict) -> str:
    """Generate a readable usage line."""
    examples = cmd.get("syntax_examples", []) or cmd.get("usage_examples", [])
    if examples:
        return f"Usage: {examples[0]}"
    args = cmd.get("args", [])
    if args:
        return f"Usage: {cmd_name} " + " ".join(str(a) for a in args)
    return f"Usage: {cmd_name}"


def _print_section(title: str, color_name: str, entries: list, is_tool: bool = False):
    """Pretty section printer using indent_wrap for consistent formatting."""
    if not entries:
        return

    width = get_terminal_width()

    print_formatted_text(ANSI(color(f"[{title.upper()}]", color_name, bold=True)))
    draw_line("-", "white", width=width)

    if is_tool:
        names = [entry[0] for entry in entries]
    else:
        names = [entry.get("name") or entry.get("symbol") for entry in entries]

    max_len = max(len(n) for n in names) if names else 10

    for entry in entries:
        if is_tool:
            name, data = entry
            summary = data.get("summary") or data.get("description") or ""
        else:
            name = entry.get("name") or entry.get("symbol")
            summary = entry.get("summary") or entry.get("description") or ""

        spacing = " " * (max_len - len(name) + 2)
        prefix = f"{name}{spacing}{ARROW}"

        lines = indent_wrap(
            text=summary,
            indent=2,
            prefix=prefix,
            prefix_color=color_name,
            text_color="white",
            bold_prefix=True,
            pad_prefix=True,
        )

        for line in lines:
            print_formatted_text(ANSI(line))

    print()


def handle_help(arg: str = ""):
    """Main entrypoint for the help command."""
    arg = (arg or "").strip()
    utils = get_utils_commands()
    tools = get_tools()
    operators = get_operators()

    if not arg:
        width = get_terminal_width()
        _print_section("UTILS", "green", utils)
        _print_section("TOOLS", "cyan", list(tools.items()), is_tool=True)
        _print_section("OPERATORS", "yellow", operators)
        draw_line("-", "white", width=width)

        print_formatted_text(
            ANSI(
                color(
                    "  Type 'help <command|tool|operator>' for detailed syntax and examples.",
                    "cyan",
                )
            )
        )

        draw_line("-", "white", width=width)
        return

    for cmd in utils:
        if arg == cmd.get("name") or arg in cmd.get("aliases", []):
            _show_detailed_help(cmd.get("name"), cmd, "green", "UTIL COMMAND")
            return

    if arg in tools:
        _show_detailed_help(arg, tools[arg], "cyan", "TOOL")
        return

    for op in operators:
        if arg == op.get("symbol") or arg == op.get("name"):
            _show_detailed_help(arg, op, "yellow", "OPERATOR")
            return

    print_error(f"No such command, tool, or operator: {arg}")


def _show_detailed_help(name: str, data: dict, color_name: str, category: str):
    """Render detailed help view with wrapped paragraphs and consistent indentation."""
    width = get_terminal_width()

    draw_line("-", color_name, width=width)
    print_formatted_text(
        ANSI(color(f"  {category}: {name}", color_name, bold=True))
    )
    draw_line("-", color_name, width=width)
    print()

    # description
    desc = data.get("details") or data.get("description") or data.get("summary", "")
    if desc:
        for line in indent_wrap(desc, indent=2, text_color="white"):
            print_formatted_text(ANSI(line))
        print()

    # usage
    usage = _format_usage(name, data)
    print_formatted_text(ANSI(color("  " + usage, "yellow")))

    # arguments
    args = data.get("args", {})
    if args:
        print()
        print_formatted_text(ANSI(color("  Arguments:", "cyan", bold=True)))

        if isinstance(args, dict):
            for arg_name, meta in args.items():
                t = meta.get("type", "string")
                req = "required" if meta.get("required") else "optional"
                desc_text = meta.get("description", meta.get("desc", ""))
                arg_prefix = f"- {arg_name} ({t}, {req})"

                for line in indent_wrap(
                    text=desc_text,
                    indent=4,
                    prefix=arg_prefix,
                    prefix_color="green",
                    text_color="white",
                    bold_prefix=False,
                ):
                    print_formatted_text(ANSI(line))

        elif isinstance(args, list):
            for a in args:
                print_formatted_text(ANSI(color(f"    - {a}", "green")))

    # behavior
    behavior = data.get("behavior", {})
    if behavior:
        print()
        print_formatted_text(ANSI(color("  Behavior:", "cyan", bold=True)))
        for k, v in behavior.items():
            for line in indent_wrap(f"{k}: {v}", indent=4, text_color="white"):
                print_formatted_text(ANSI(line))

    # examples
    examples = data.get("syntax_examples", data.get("usage_examples", []))
    if examples:
        print()
        print_formatted_text(ANSI(color("  Examples:", "cyan", bold=True)))
        for ex in examples:
            for line in indent_wrap(ex, indent=4, text_color="white"):
                print_formatted_text(ANSI(line))

    print()
    draw_line("-", color_name, width=width)
