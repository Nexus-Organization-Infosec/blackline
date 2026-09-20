"""Data contracts for the Pathfinder subsystem."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """The executable identity contract for one external dependency."""

    name: str
    executable: str
    provider: str = ""
    check_args: tuple[str, ...] = ()
    check_success_codes: tuple[int, ...] = (0,)
    identity_markers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolResolution:
    """A discovered executable and the outcome of its identity check."""

    name: str
    provider: str = ""
    path: str = ""
    version: str = ""
    valid: bool = False
    detail: str = ""
    candidates: tuple[str, ...] = ()

    @property
    def found(self) -> bool:
        """Whether any matching executable name was found."""
        return bool(self.candidates)
