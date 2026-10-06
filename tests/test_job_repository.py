"""Contracts for swappable, backward-compatible job persistence."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from blackline.core.jobs import Job, build_job_summary
from blackline.storage.job_store import JobRepository, JsonJobRepository


class JobRepositoryTests(unittest.TestCase):
    def test_json_repository_round_trips_versioned_jobs_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            repository = JsonJobRepository(Path(tmp))
            job = Job(
                "A12F",
                "recon",
                {"target": "example.com"},
                "2026-10-06 12:00",
                target="example.com",
                target_type="domain",
                summary=build_job_summary(target="example.com", target_type="domain", steps=(), legacy_results=()),
            )

            path = repository.save(job)
            loaded = repository.load("#a12f")

            self.assertEqual(path.name, "A12F.json")
            self.assertEqual(loaded, job)
            self.assertEqual(json.loads(path.read_text())["schema_version"], 1)
            self.assertEqual(list(Path(tmp).glob("*.tmp")), [])

    def test_repository_upgrades_legacy_jobs_on_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "OLD1.json").write_text(
                json.dumps(
                    {
                        "id": "OLD1",
                        "module": "recon",
                        "params": {"target": "192.0.2.1"},
                        "created": "2026-01-01 00:00",
                        "results": [
                            {
                                "tool": "dns",
                                "action": "resolve",
                                "ok": True,
                                "payload": {"resolved_ips": ["192.0.2.1"]},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            job = JsonJobRepository(root).load("OLD1")

            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job.target_type, "ip")
            self.assertEqual(job.status, "completed")
            self.assertEqual(job.steps[0]["name"], "resolve")

    def test_corrupt_jobs_do_not_break_repository_listing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = JsonJobRepository(root)
            repository.save(Job("GOOD", "manual", {}, "2026-10-06 12:00"))
            (root / "BROKEN.json").write_text("{not-json", encoding="utf-8")

            self.assertEqual([job.id for job in repository.list()], ["GOOD"])

    def test_json_repository_satisfies_storage_protocol(self):
        repository: JobRepository = JsonJobRepository(Path("unused"))

        self.assertTrue(callable(repository.append_result))


if __name__ == "__main__":
    unittest.main()
