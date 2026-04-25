"""Prompt-toolkit backed interactive input."""

from __future__ import annotations

from typing import Any

from blackline.utils.tab_complete import command_spans, completion_items, current_completion_length

PromptFragments = list[tuple[str, str]]


def create_prompt_session() -> Any | None:
    """Create a rich prompt session when prompt_toolkit is installed."""
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import Completer, Completion
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.lexers import Lexer
        from prompt_toolkit.styles import Style
    except ImportError:
        return None

    class BlacklineCompleter(Completer):
        def get_completions(self, document: Any, complete_event: Any) -> Any:
            text = document.text_before_cursor
            word = document.get_word_before_cursor(WORD=True)
            replacement_length = current_completion_length(text, word)
            for suggestion, metadata in completion_items(text):
                yield Completion(suggestion, start_position=-replacement_length, display_meta=metadata)

    class BlacklineLexer(Lexer):
        def lex_document(self, document: Any) -> Any:
            spans = command_spans(document.text)

            def get_line(line_number: int) -> list[tuple[str, str]]:
                if line_number != 0:
                    return [("", "")]
                return _style_line(document.text, spans)

            return get_line

    bindings = KeyBindings()

    @bindings.add("enter")
    def _(event: Any) -> None:
        buffer = event.app.current_buffer
        complete_state = buffer.complete_state
        if complete_state and complete_state.current_completion:
            buffer.apply_completion(complete_state.current_completion)
            return
        buffer.validate_and_handle()

    return PromptSession(
        completer=BlacklineCompleter(),
        complete_while_typing=True,
        key_bindings=bindings,
        lexer=BlacklineLexer(),
        style=Style.from_dict(
            {
                "cmd.valid": "#87af87",
                "cmd.invalid": "#af6f6f",
                "hint": "#6f6f6f",
                "prompt.name": "ansibrightgreen",
                "prompt.bracket": "ansiwhite",
                "prompt.job": "ansibrightcyan",
                "prompt.arrow": "ansibrightyellow",
            }
        ),
    )


def prompt_fragments(active_job: str = "") -> PromptFragments:
    """Return a prompt-toolkit-native prompt."""
    if active_job:
        return [
            ("class:prompt.name", "bl"),
            ("class:prompt.bracket", " ["),
            ("class:prompt.job", f"#{active_job}"),
            ("class:prompt.arrow", "] ❯ "),
        ]
    return [
        ("class:prompt.name", "blackline"),
        ("class:prompt.arrow", " ❯ "),
    ]


def _style_line(text: str, spans: list[tuple[int, int, bool]]) -> list[tuple[str, str]]:
    fragments: list[tuple[str, str]] = []
    cursor = 0
    for start, end, valid in spans:
        if cursor < start:
            fragments.append(("", text[cursor:start]))
        style = "class:cmd.valid" if valid else "class:cmd.invalid"
        fragments.append((style, text[start:end]))
        cursor = end
    if cursor < len(text):
        fragments.append(("", text[cursor:]))
    return fragments
