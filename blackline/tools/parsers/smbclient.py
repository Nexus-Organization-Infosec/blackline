"""Parse machine-readable anonymous share listings from smbclient."""

from __future__ import annotations


def parse_smbclient_grepable(stdout: str) -> list[dict[str, str]]:
    """Return shares from ``smbclient -g -L`` output.

    Samba's grepable form emits ``TYPE|NAME|COMMENT`` records.  Discovery is
    deliberately limited to share metadata; Blackline does not authenticate,
    open, download, or modify remote content here.
    """
    shares: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in (stdout or "").splitlines():
        kind, separator, remainder = line.partition("|")
        if not separator or kind.lower() not in {"disk", "ipc", "printer"}:
            continue
        name, separator, comment = remainder.partition("|")
        name = name.strip()
        if not name or (kind.lower(), name.lower()) in seen:
            continue
        normalized_kind = kind.lower()
        seen.add((normalized_kind, name.lower()))
        shares.append({"name": name, "type": normalized_kind, "comment": comment.strip() if separator else ""})
    return sorted(shares, key=lambda share: (share["type"], share["name"].lower()))
