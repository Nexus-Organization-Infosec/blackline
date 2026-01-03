from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

from utils.display import print_error
from utils.shell.completer import BlacklineCompleter


class ShellSession:
    """Owns the prompt_toolkit event loop."""

    def __init__(self, shell, history, prompt):
        self.shell = shell
        self.prompt = prompt
        self.dispatcher = shell.dispatcher

        self.session = PromptSession(
            history=history.input_history(),
            completer=BlacklineCompleter(),
            auto_suggest=AutoSuggestFromHistory(),
        )

    def run(self):
        """
        Ctrl+C  -> cancel input, new prompt
        Ctrl+D  -> exit shell
        """
        with patch_stdout():
            while True:
                try:
                    line = self.session.prompt(self.prompt)

                except EOFError:
                    print()
                    break

                except KeyboardInterrupt:
                    print()
                    continue

                if not line.strip():
                    continue
                try:
                    should_exit = self.dispatcher.dispatch(line)
                    if should_exit:
                        break
                except Exception as e:
                    print_error(f"Command error: {e}")
