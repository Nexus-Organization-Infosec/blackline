from prompt_toolkit.formatted_text import ANSI
from utils.colors import color


def get_prompt() -> ANSI:
    return ANSI(
        color("blackline ", "turquoise", bold=True)
        + color("❯ ", "yellow", bold=True)
    )
