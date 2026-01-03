from __future__ import annotations

from utils.display import print_info, print_warning, print_error
from utils.shell.state import ShellState
from utils.shell.session import ShellSession
from utils.shell.prompt import get_prompt
from utils.shell.dispatcher import ShellDispatcher
from utils.shell.history import History

from frontend.commands.utils.clear_cmd import handle_clear
from frontend.commands.utils.version_cmd import handle_version
from frontend.commands.utils.help_cmd import handle_help
from frontend.commands.utils.debug_cmd import handle_debug

from frontend.parser.intent_parser import parse_intent
from midend.api import submit_intent
from backend.runner import run_task


class BLShell:
    def __init__(self):
        self.state = ShellState()
        self.history = History()

        self.prompt = get_prompt()
        self.dispatcher = ShellDispatcher(self)
        self.session = ShellSession(
            shell=self,
            history=self.history,
            prompt=self.prompt,
        )

    def run(self):
        print_info("Type 'help' to get started. \n")
        self.session.run()

    def do_clear(self, _arg: str = ""):
        handle_clear()

    def do_version(self, _arg: str = ""):
        handle_version()

    def do_help(self, arg: str = ""):
        handle_help(arg)

    def do_history(self, arg: str = ""):
        return self.history.handle(arg)

    def do_debug(self, arg: str = ""):
        handle_debug(self.state, arg)

    def do_exit(self, _arg: str = ""):
        print_info("Goodbye.")
        return True

    def do_quit(self, _arg: str = ""):
        return self.do_exit()
    
    def run_action(self, line: str):
        intent = parse_intent(line)
        tasks = submit_intent(intent)

        if not tasks:
            print_warning("No tasks generated.")
            return

        for task in tasks:
            result = run_task(task)

            if result.get("stdout"):
                print(result["stdout"], end="")

            if result.get("stderr"):
                print_error(result["stderr"])

            if self.state.debug and result.get("data"):
                print(result["data"])
