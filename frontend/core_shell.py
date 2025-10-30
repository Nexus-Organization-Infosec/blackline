import cmd
import shlex

from utils.colors import color
from utils.display import print_info, print_warning, print_error

from frontend.commands.utils.clear_cmd import handle_clear
from frontend.commands.utils.version_cmd import handle_version
from frontend.commands.utils.help_cmd import handle_help


class BLShell(cmd.Cmd):
    base_prompt = color("blackline ", "red", bold=True) + color("> ", "yellow")
    intro = color("Type 'help' to get started.", "cyan")

    def __init__(self):
        super().__init__()
        self.cfg = {}

    @property
    def prompt(self):
        """Print an empty line above the prompt, keeping input on same line."""
        return f"{self.base_prompt}"

    # core commands 
    def do_clear(self, _):
        """Clear the terminal screen."""
        handle_clear()

    def do_version(self, _):
        """Show current Blackline version."""
        handle_version()

    def do_help(self, arg):
        """Show command help."""
        handle_help(arg)

    def do_exit(self, _):
        """Exit the Blackline shell."""
        print_info("Goodbye.")
        return True

    def do_quit(self, _):
        """Alias for 'exit'."""
        return self.do_exit(_)

    # command behavior 
    def emptyline(self):
        """Do nothing on empty input."""
        pass

    def default(self, line):
        """Handle unrecognized commands gracefully."""
        if not line.strip():
            return

        try:
            words = shlex.split(line)
        except ValueError as e:
            print_error(f"Invalid syntax: {e}")
            return

        cmd_input = words[0].lower()
        print_error(f"Unknown command: {cmd_input}")
        print_info("Type 'help' to see available commands.")

    def onecmd(self, line):
        """Run a single command with spacing around output."""
        line = line.strip()
        if not line:
            return super().onecmd(line)
        print()
        result = super().onecmd(line)
        if result is not True:
            print()

        return result

    # REPL loop
    def cmdloop(self, intro=None):
        """Main REPL loop with Ctrl+C handling."""
        try:
            super().cmdloop(intro or self.intro)
        except KeyboardInterrupt:
            print_warning("\n[CTRL+C] Interrupted. Type 'exit' or 'quit' to quit.")
            self.cmdloop()
