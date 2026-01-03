from utils.display import print_error


class ShellDispatcher:
    """Decides whether input is a shell command or an action """

    def __init__(self, shell):
        self.shell = shell

    def dispatch(self, line: str) -> bool:
        parts = line.strip().split(maxsplit=1)
        cmd = parts[0]
        arg = parts[1] if len(parts) > 1 else ""

        handler = getattr(self.shell, f"do_{cmd}", None)
        if handler:
            return bool(handler(arg))

        self.shell.run_action(line)
        return False
