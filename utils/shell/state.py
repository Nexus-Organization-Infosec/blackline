from dataclasses import dataclass


@dataclass
class ShellState:
    debug: bool = False
