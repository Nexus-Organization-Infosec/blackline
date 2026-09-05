"""Small JSON persistence adapter for registered template metadata."""

from __future__ import annotations

import json
from pathlib import Path

from blackline.templates.models import Template, TemplateStatus


class TemplateStorage:
    """Persist source registrations separately from compiled runtime objects."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_template_registry_path()

    def load(self) -> tuple[Template, ...]:
        """Load persisted registrations; malformed storage fails safely as empty."""
        if not self.path.exists():
            return ()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return ()
        items = data.get("templates", []) if isinstance(data, dict) else []
        templates: list[Template] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                templates.append(
                    Template(
                        name=str(item["name"]),
                        path=Path(str(item["path"])),
                        source_hash=str(item.get("source_hash", "")),
                        status=TemplateStatus(str(item.get("status", TemplateStatus.LOADED.value))),
                        last_valid_hash=str(item.get("last_valid_hash", "")),
                        last_error=str(item.get("last_error", "")),
                    )
                )
            except (KeyError, ValueError):
                continue
        return tuple(templates)

    def save(self, templates: tuple[Template, ...]) -> None:
        """Persist registrations atomically without writing compiled CLT IR."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "templates": [
                {
                    "name": template.name,
                    "path": str(template.path),
                    "source_hash": template.source_hash,
                    "status": template.status.value,
                    "last_valid_hash": template.last_valid_hash,
                    "last_error": template.last_error,
                }
                for template in sorted(templates, key=lambda item: item.name)
            ]
        }
        temporary = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(self.path)


def default_template_registry_path() -> Path:
    """Return the Blackline-owned metadata location, not user template source."""
    return Path(__file__).resolve().parents[1] / "storage" / "templates" / "registry.json"
