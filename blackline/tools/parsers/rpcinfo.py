"""Parse the tabular output of ``rpcinfo -p``."""

from __future__ import annotations


def parse_rpcinfo_table(stdout: str) -> list[dict[str, object]]:
    """Return normalized portmapper registrations from standard rpcinfo output."""
    records: list[dict[str, object]] = []
    for line in (stdout or "").splitlines():
        columns = line.split()
        if len(columns) < 4 or not columns[0].isdigit() or not columns[1].isdigit() or not columns[3].isdigit():
            continue
        records.append(
            {
                "program": int(columns[0]),
                "version": int(columns[1]),
                "protocol": columns[2].lower(),
                "port": int(columns[3]),
                "service": " ".join(columns[4:]),
            }
        )
    return records
