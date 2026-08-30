"""Recon domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from urllib.parse import urlsplit

_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)


class InvalidReconTargetError(ValueError):
    """Raised when a recon target cannot be normalized."""


@dataclass(frozen=True, slots=True)
class ReconTarget:
    """Normalized recon target description."""

    raw: str
    target_type: str
    host: str = ""
    scheme: str = ""
    path: str = ""
    port: str = ""

    @property
    def scan_target(self) -> str:
        """Return the host-like value downstream steps should use."""
        return self.host or self.raw


@dataclass(frozen=True, slots=True)
class ReconStep:
    """One domain-level recon step."""

    name: str
    inputs: dict[str, object] = field(default_factory=dict)
    tool: str = ""


def normalize_recon_target(raw_target: str) -> ReconTarget:
    """Normalize a raw target into a deterministic recon target model."""
    raw = raw_target.strip()
    if not raw:
        raise InvalidReconTargetError("missing required recon argument: target")
    if any(character.isspace() for character in raw):
        raise InvalidReconTargetError(f"invalid recon target: {raw_target}")

    if "://" in raw:
        return _normalize_url_target(raw)

    if _looks_like_ip_target(raw):
        return _normalize_ip_target(raw)

    if _is_domain_target(raw):
        return ReconTarget(raw=raw_target, target_type="domain", host=raw.lower())

    raise InvalidReconTargetError(f"invalid recon target: {raw_target}")


def _normalize_url_target(raw: str) -> ReconTarget:
    parts = urlsplit(raw)
    if not parts.scheme or not parts.netloc:
        raise InvalidReconTargetError(f"invalid recon target: {raw}")

    host = (parts.hostname or "").strip().lower()
    if not host:
        raise InvalidReconTargetError(f"invalid recon target: {raw}")
    if not (_looks_like_ip_target(host) or _is_domain_target(host)):
        raise InvalidReconTargetError(f"invalid recon target: {raw}")

    try:
        port = str(parts.port) if parts.port else ""
    except ValueError as exc:
        raise InvalidReconTargetError(f"invalid recon target: {raw}") from exc

    path = parts.path or ""
    if parts.query:
        path = f"{path}?{parts.query}" if path else f"?{parts.query}"
    if parts.fragment:
        path = f"{path}#{parts.fragment}" if path else f"#{parts.fragment}"

    return ReconTarget(
        raw=raw,
        target_type="url",
        host=host,
        scheme=parts.scheme.lower(),
        path=path,
        port=port,
    )


def _normalize_ip_target(raw: str) -> ReconTarget:
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise InvalidReconTargetError(f"invalid recon target: {raw}") from exc
    return ReconTarget(raw=raw, target_type="ip", host=str(address))


def _looks_like_ip_target(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return bool(re.fullmatch(r"[0-9a-fA-F:.]+", value)) and ":" in value or bool(re.fullmatch(r"[0-9.]+", value))
    return True


def _is_domain_target(value: str) -> bool:
    candidate = value.rstrip(".")
    if not candidate or ".." in candidate or "/" in candidate or "@" in candidate:
        return False

    labels = candidate.split(".")
    if any(not label for label in labels):
        return False
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        return False
    return any(any(character.isalpha() for character in label) for label in labels)
