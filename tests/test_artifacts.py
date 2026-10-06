"""Contracts for canonical cross-step artifacts."""

from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from blackline.cli.commands.recon.recon_cmd import record_job_result
from blackline.cli.commands.system.jobs_cmd import handle_new, load_job
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.core.artifacts import Artifact, ArtifactStore
from blackline.engine.models import StepResult


class ArtifactStoreTests(unittest.TestCase):
    def test_store_deduplicates_exact_facts_but_preserves_provenance(self):
        first = Artifact(
            "host.port",
            "192.0.2.10",
            {"port": 443, "protocol": "tcp", "state": "open"},
            source_step="naabu.scan.1",
            source_provider="naabu",
        )
        corroborating = Artifact(
            "host.port",
            "192.0.2.10",
            {"port": 443, "protocol": "tcp", "state": "open"},
            source_step="nmap.scan.1",
            source_provider="nmap",
        )
        store = ArtifactStore((first, first, corroborating))

        self.assertEqual(len(store), 2)
        self.assertEqual(store.find("host.port", source_provider="naabu"), (first,))
        self.assertEqual(store.find("host.port", source_provider="nmap"), (corroborating,))

    def test_snapshot_is_independent_and_keeps_deterministic_order(self):
        store = ArtifactStore((Artifact("host.ip", "192.0.2.10"),))
        snapshot = store.snapshot()
        snapshot.add(Artifact("host.ip", "192.0.2.11"))

        self.assertEqual([item.subject for item in store.all()], ["192.0.2.10"])
        self.assertEqual([item.subject for item in snapshot.all()], ["192.0.2.10", "192.0.2.11"])

    def test_step_result_carries_artifacts_without_changing_payload_contract(self):
        artifact = Artifact("dns.record", "example.com", {"type": "A", "value": "192.0.2.10"})
        result = StepResult("dns", "dns", True, {"records": {"A": ["192.0.2.10"]}}, artifacts=(artifact,))

        self.assertEqual(result.payload["records"], {"A": ["192.0.2.10"]})
        self.assertEqual(result.artifacts, (artifact,))
        self.assertEqual(result.outcome, "done")

    def test_job_storage_persists_artifacts_with_their_step(self):
        artifact = Artifact(
            "host.ip",
            "192.0.2.10",
            {"host": "example.com"},
            source_step="dns.dns.1",
            source_provider="dnspython",
        )
        result = StepResult(
            "dns",
            "dns",
            True,
            {"target": "example.com", "records": {"A": ["192.0.2.10"]}, "resolved_ips": ["192.0.2.10"]},
            artifacts=(artifact,),
        )
        with tempfile.TemporaryDirectory() as directory:
            jobs_root = Path(directory)
            state = ShellState()
            handle_new("recon[target=example.com]", state, jobs_root=jobs_root, job_id="ART1", render_summary=False, announce_entry=False)
            record_job_result("ART1", result, result.payload, jobs_root=jobs_root)
            job = load_job("ART1", jobs_root)

        self.assertIsNotNone(job)
        assert job is not None
        self.assertEqual(job.results[0]["artifacts"][0]["kind"], "host.ip")
        self.assertEqual(job.steps[0]["artifacts"][0]["subject"], "192.0.2.10")


if __name__ == "__main__":
    unittest.main()
