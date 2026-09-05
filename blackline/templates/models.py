"""Models used by the reusable Blackline template subsystem."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from blackline.clt.ir import WorkflowIR


class TemplateStatus(str, Enum):
    """The structured validity state of one registered template."""

    LOADED = "loaded"
    INVALID = "invalid"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class Template:
    """A registered `.bline` source and its most recent valid compilation."""

    name: str
    path: Path
    source_hash: str = ""
    status: TemplateStatus = TemplateStatus.LOADED
    compiled: WorkflowIR | None = field(default=None, repr=False, compare=False)
    last_valid_hash: str = ""
    last_error: str = ""

    @property
    def has_last_valid_compilation(self) -> bool:
        """Return whether this process can safely run a last-known-good workflow."""
        return self.compiled is not None


class TemplateError(ValueError):
    """Base error for registry and template lifecycle failures."""


class TemplateNotFoundError(TemplateError):
    """Raised when a registered template name is unknown."""


class TemplateSourceError(TemplateError):
    """Raised when a source path is invalid, missing, or unreadable."""


class DuplicateTemplateError(TemplateError):
    """Raised when a distinct source claims an already registered name."""
