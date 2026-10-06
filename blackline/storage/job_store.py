"""Repository-backed job persistence with a versioned JSON implementation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import random
import string
from tempfile import NamedTemporaryFile
from threading import RLock
from typing import Protocol

from blackline.core.jobs import Job, append_result, job_from_dict, normalize_job_id

ID_ALPHABET = string.ascii_uppercase + string.digits


class JobRepository(Protocol):
    """Storage contract implemented independently of the CLI and engine."""

    def save(self, job: Job) -> Path: ...

    def load(self, identifier: str) -> Job | None: ...

    def list(self) -> list[Job]: ...

    def delete(self, identifier: str) -> bool: ...

    def new_id(self) -> str: ...

    def append_result(self, identifier: str, entry: dict[str, object]) -> bool: ...


class JsonJobRepository:
    """Persist jobs as backward-compatible, atomically replaced JSON files."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._lock = RLock()

    def save(self, job: Job) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / f"{normalize_job_id(job.id)}.json"
        serialized = json.dumps(job.to_dict(), indent=2) + "\n"
        temporary_path: Path | None = None
        try:
            with NamedTemporaryFile("w", encoding="utf-8", dir=self.root, prefix=f".{path.stem}.", suffix=".tmp", delete=False) as file:
                file.write(serialized)
                file.flush()
                os.fsync(file.fileno())
                temporary_path = Path(file.name)
            os.replace(temporary_path, path)
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()
        return path

    def load(self, identifier: str) -> Job | None:
        path = self.root / f"{normalize_job_id(identifier)}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return job_from_dict(data) if isinstance(data, dict) else None

    def list(self) -> list[Job]:
        if not self.root.exists():
            return []
        return [job for path in sorted(self.root.glob("*.json")) if (job := self.load(path.stem)) is not None]

    def delete(self, identifier: str) -> bool:
        path = self.root / f"{normalize_job_id(identifier)}.json"
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        return True

    def new_id(self) -> str:
        while True:
            identifier = "".join(random.choice(ID_ALPHABET) for _ in range(4))
            if not (self.root / f"{identifier}.json").exists():
                return identifier

    def append_result(self, identifier: str, entry: dict[str, object]) -> bool:
        with self._lock:
            job = self.load(identifier)
            if job is None:
                return False
            self.save(append_result(job, entry))
        return True


def default_jobs_root() -> Path:
    """Return the current default job storage path."""
    return Path(__file__).resolve().parent / "jobs"


def repository(jobs_root: Path | None = None) -> JsonJobRepository:
    """Build the default repository adapter for a storage root."""
    return JsonJobRepository(jobs_root or default_jobs_root())


def save_job(job: Job, jobs_root: Path) -> Path:
    return repository(jobs_root).save(job)


def load_job(identifier: str, jobs_root: Path) -> Job | None:
    return repository(jobs_root).load(identifier)


def list_jobs(jobs_root: Path | None = None) -> list[Job]:
    return repository(jobs_root).list()


def list_job_ids(jobs_root: Path | None = None) -> list[str]:
    return [job.id for job in list_jobs(jobs_root)]


def generate_job_id(jobs_root: Path) -> str:
    return repository(jobs_root).new_id()


def append_job_result(identifier: str, entry: dict[str, object], jobs_root: Path | None = None) -> bool:
    return repository(jobs_root).append_result(identifier, entry)
