# frontend/core_shell.py 

import cmd
import shlex 

from utils.colors import color 
from utils.display import print_info, print_warning, print_error

from frontend.commands.utils.clear_cmd import handle_clear

class BLShell(cmd.Cmd):
    prompt = color("blackline ", "yellow", bold = True) + color("> ", "green")
    intro = color("Type 'help' to get started.\n", "cyan")

    def __init__(self):
        super().__init__()
        self.cfg = {}

    def do_clear(self, _):
        """Clear the terminal screen."""
        handle_clear()

    def do_exit(self, _):
        """Exit the Blackline shell."""
        print_info("Goodbye.")
        return True
    
    def do_quit(self, _):
        """Alias for 'exit'."""
        return self.do_exit(_)
    
    def emptyline(self):
        """Do nothing on empty input."""
        pass

    def default(self, line):
        """Handle unrecognized commands with a friendly error + suggestion hook."""
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

    def cmdloop(self, intro=None):
        """Main REPL loop with Ctrl+C handling."""
        try:
            super().cmdloop(intro or self.intro)
        except KeyboardInterrupt:
            print_warning("\n[CTRL+C] Interrupted. Type 'exit' or 'quit' to quit.")
            self.cmdloop()