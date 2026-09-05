"""Transactional template registration and CLT compilation lifecycle."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import re

from blackline.clt.compiler import compile_source
from blackline.clt.errors import CLTError
from blackline.clt.vocabulary import Vocabulary, default_vocabulary
from blackline.templates.models import (
    DuplicateTemplateError,
    Template,
    TemplateError,
    TemplateNotFoundError,
    TemplateSourceError,
    TemplateStatus,
)
from blackline.templates.storage import TemplateStorage

_TEMPLATE_NAME = re.compile(r"^[a-z][a-z0-9-]*$")


class TemplateRegistry:
    """Own template identity, validation, refresh, and persistent registration."""

    def __init__(self, *, storage: TemplateStorage | None = None, vocabulary: Vocabulary | None = None) -> None:
        self.storage = storage or TemplateStorage()
        self.vocabulary = vocabulary or default_vocabulary()
        self._templates = {template.name: template for template in self.storage.load()}

    def register(self, path: str | Path) -> Template:
        """Compile a `.bline` file before atomically making it available."""
        source_path = _resolve_source_path(path)
        name = _template_name(source_path)
        existing = self._templates.get(name)
        if existing and existing.path != source_path:
            raise DuplicateTemplateError(f"template name already registered: {name}")
        source, source_hash, compiled = _read_and_compile(source_path, self.vocabulary)
        del source  # Source remains owned by the user; only its hash is registered.
        template = Template(
            name=name,
            path=source_path,
            source_hash=source_hash,
            status=TemplateStatus.LOADED,
            compiled=compiled,
            last_valid_hash=source_hash,
        )
        self._templates[name] = template
        self._persist()
        return template

    def list(self, *, refresh: bool = True) -> tuple[Template, ...]:
        """Return known templates and refresh external source changes by default."""
        if refresh:
            for name in tuple(self._templates):
                self.refresh(name)
        return tuple(sorted(self._templates.values(), key=lambda template: template.name))

    def get(self, name: str, *, refresh: bool = False) -> Template:
        """Resolve a template by registered identity."""
        normalized = _normalize_name(name)
        if normalized not in self._templates:
            raise TemplateNotFoundError(f"template not found: {name}")
        return self.refresh(normalized) if refresh else self._templates[normalized]

    def refresh(self, name: str) -> Template:
        """Recompile changed source transactionally, retaining last valid IR on error."""
        template = self.get(name, refresh=False)
        if not template.path.exists():
            updated = replace(template, status=TemplateStatus.MISSING, last_error=f"template source is missing: {template.path}")
            self._replace(updated)
            return updated
        try:
            source, source_hash, compiled = _read_and_compile(template.path, self.vocabulary)
            del source
        except CLTError as exc:
            source_hash = _source_hash_if_readable(template.path)
            updated = replace(
                template,
                source_hash=source_hash,
                status=TemplateStatus.INVALID,
                last_error=str(exc),
            )
            self._replace(updated)
            return updated
        except TemplateSourceError as exc:
            updated = replace(template, status=TemplateStatus.MISSING, last_error=str(exc))
            self._replace(updated)
            return updated

        if (
            template.status is TemplateStatus.LOADED
            and template.source_hash == source_hash
            and template.compiled is not None
        ):
            return template
        updated = replace(
            template,
            source_hash=source_hash,
            status=TemplateStatus.LOADED,
            compiled=compiled,
            last_valid_hash=source_hash,
            last_error="",
        )
        self._replace(updated)
        return updated

    def executable(self, name: str) -> Template:
        """Return the valid current or last-valid compiled template for explicit run."""
        template = self.get(name, refresh=True)
        if template.status is TemplateStatus.MISSING:
            raise TemplateSourceError(template.last_error)
        if template.compiled is None:
            raise TemplateError(template.last_error or f"template has no valid compilation: {template.name}")
        return template

    def remove(self, name: str) -> Template:
        """Unregister a template without touching the user-owned source file."""
        template = self.get(name)
        del self._templates[template.name]
        self._persist()
        return template

    def _replace(self, template: Template) -> None:
        self._templates[template.name] = template
        self._persist()

    def _persist(self) -> None:
        self.storage.save(tuple(self._templates.values()))


def _resolve_source_path(path: str | Path) -> Path:
    source_path = Path(path).expanduser()
    # `load web-audit` is a convenient spelling of `load web-audit.bline`
    # when the source exists beside the current shell directory.
    if not source_path.suffix and not source_path.exists():
        source_path = source_path.with_suffix(".bline")
    if source_path.suffix.lower() != ".bline":
        raise TemplateSourceError("template source must use the .bline extension")
    try:
        resolved = source_path.resolve(strict=True)
    except OSError as exc:
        raise TemplateSourceError(f"template source not found: {source_path}") from exc
    if not resolved.is_file():
        raise TemplateSourceError(f"template source is not a file: {resolved}")
    return resolved


def _template_name(path: Path) -> str:
    name = path.stem.lower()
    if not _TEMPLATE_NAME.fullmatch(name):
        raise TemplateSourceError("template names must start with a letter and use lowercase letters, numbers, or hyphens")
    return name


def _normalize_name(name: str) -> str:
    normalized = name.strip().lower()
    if not normalized:
        raise TemplateNotFoundError("template name is required")
    return normalized


def _read_and_compile(path: Path, vocabulary: Vocabulary):
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TemplateSourceError(f"cannot read template source: {path}") from exc
    source_hash = sha256(source.encode()).hexdigest()
    return source, source_hash, compile_source(source, filename=str(path), vocabulary=vocabulary)


def _source_hash_if_readable(path: Path) -> str:
    try:
        return sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""
