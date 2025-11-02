import cmd
import shlex
import readline

from utils.colors import color
from utils.display import print_info, print_warning, print_error

from frontend.commands.utils.clear_cmd import handle_clear
from frontend.commands.utils.version_cmd import handle_version
from frontend.commands.utils.help_cmd import handle_help
from frontend.commands.utils.history_cmd import handle_history, record_history

from utils.tab_complete import (
    complete_command,
    complete_help,
    complete_history,
    complete_tools,
)

class BLShell(cmd.Cmd):
    """Core interactive shell for Blackline."""
    base_prompt = color("blackline ", "turquoise", bold=True) + color("❯ ", "yellow", bold=True)
    intro = color("Type 'help' to get started.\n", "cyan")

    def __init__(self):
        super().__init__()
        self.cfg = {}

    @property
    def prompt(self):
        """Print an empty line above the prompt for visual spacing."""
        return f"{self.base_prompt}"

    #  core commands 
    def do_clear(self, _):
        """Clear the terminal screen."""
        handle_clear()

    def do_version(self, _):
        """Show current Blackline version."""
        handle_version()

    def do_help(self, arg):
        """Show command help."""
        handle_help(arg)

    def do_history(self, arg):
        """Show or manage command history."""
        handle_history(self.cfg, arg)

    def do_exit(self, _):
        """Exit the Blackline shell."""
        print_info("Goodbye.")
        return True

    def do_quit(self, _):
        """Alias for 'exit'."""
        return self.do_exit(_)

    # tab completions 
    def completenames(self, text, *ignored):
        """Global completion for all top-level commands and tools."""
        return complete_command(text, self.lastcmd or "", 0, 0)

    def complete_help(self, text, line, begidx, endidx):
        """Autocomplete for the help command."""
        return complete_help(text, line, begidx, endidx)

    def complete_history(self, text, line, begidx, endidx):
        """Autocomplete for history command."""
        return complete_history(text, line, begidx, endidx)

    def complete_recon(self, text, line, begidx, endidx):
        """Autocomplete for tool subcommands like recon."""
        return complete_tools(text, line, begidx, endidx)

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
        """Run a single command and record history only if recognized."""
        raw_line = (line or "").strip()
        if not raw_line:
            return super().onecmd(line)
        print()
        try:
            result = super().onecmd(raw_line)
            success = True
        except Exception as e:
            print_error(f"[✗] Unexpected error: {e}")
            success = False
            result = False
        record_history(raw_line, success=success)
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
