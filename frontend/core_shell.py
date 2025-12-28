import cmd
import readline
import shlex

from utils.colors import color
from utils.display import print_info, print_warning, print_error

from frontend.commands.utils.clear_cmd import handle_clear
from frontend.commands.utils.version_cmd import handle_version
from frontend.commands.utils.help_cmd import handle_help
from frontend.commands.utils.history_cmd import handle_history, record_history

from frontend.parser.intent_parser import parse_intent
from midend.api import submit_intent
from backend.runner import run_task


class BLShell(cmd.Cmd):
    base_prompt = color("blackline ", "turquoise", bold=True) + color("❯ ", "yellow", bold=True)
    intro = color("Type 'help' to get started.\n", "cyan")

    def __init__(self):
        super().__init__()
        self.cfg = {}

    @property
    def prompt(self):
        return self.base_prompt

    # ---------- utils commands ----------

    def do_clear(self, _):
        handle_clear()

    def do_version(self, _):
        handle_version()

    def do_help(self, arg):
        handle_help(arg)

    def do_history(self, arg):
        handle_history(self.cfg, arg)

    def do_exit(self, _):
        print_info("Goodbye.")
        return True

    def do_quit(self, _):
        return self.do_exit(_)


    def emptyline(self):
        pass

    def default(self, line):
        if not line.strip():
            return

        try:
            intent = parse_intent(line)
            result = submit_intent(intent)

            if result.get("status") != "ok":
                print_error(result)
                return

            tasks = result.get("tasks", [])
            if not tasks:
                print_warning("No tasks generated.")
                return

            for task in tasks:
                output = run_task(task)
                print_info("[execution]")
                print(output)

        except Exception as e:
            print_error(f"Command error: {e}")

    def onecmd(self, line):
        raw = (line or "").strip()
        if not raw:
            return super().onecmd(line)

        print()
        try:
            result = super().onecmd(raw)
            success = True
        except Exception as e:
            print_error(f"[✗] Unexpected error: {e}")
            success = False
            result = False

        record_history(raw, success=success)

        if result is not True:
            print()

        return result

    def cmdloop(self, intro=None):
        try:
            super().cmdloop(intro or self.intro)
        except KeyboardInterrupt:
            print_warning("\n[CTRL+C] Interrupted. Type 'exit' or 'quit' to quit.")
            self.cmdloop()
