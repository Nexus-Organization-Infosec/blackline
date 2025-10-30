# utils/colors.py 

def color (text: str, color_name: str = "reset", bold: bool = False) -> str:
    colors = {
        "reset": "\033[0m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "magenta": "\033[35m",
        "cyan": "\033[36m",
        "turquoise": "\033[38;5;45m",
        "white": "\033[37m",
        "purple": "\033[0;35m",
        "dark_purple": "\033[38;5;17m",
    }

    color_code = colors.get(color_name.lower(), colors["reset"])
    if bold:
        color_code = "\033[1m" + color_code
    return f"{color_code}{text}{colors['reset']}"