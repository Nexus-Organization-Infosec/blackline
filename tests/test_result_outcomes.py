import tempfile
import unittest
from pathlib import Path

from blackline.cli.commands.system.jobs_cmd import append_job_result, handle_new, load_job
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.core.recon.outcomes import DONE, FAILED, NEGATIVE, SKIPPED, WARNING, classify_result
from blackline.engine.executor import StepResult


class ResultOutcomeTests(unittest.TestCase):
    def test_classifier_distinguishes_every_canonical_outcome(self):
        self.assertEqual(classify_result(tool="dns", ok=True, payload={}), DONE)
        self.assertEqual(classify_result(tool="dns", ok=False, payload={"negative_observation": True}), NEGATIVE)
        self.assertEqual(classify_result(tool="fingerprint", ok=True, payload={"skipped": True}), SKIPPED)
        self.assertEqual(classify_result(tool="nmap", ok=True, payload={"warnings": ["partial data"]}), WARNING)
        self.assertEqual(classify_result(tool="tls", ok=False, payload={}, error="timeout"), FAILED)

    def test_step_result_makes_negative_observations_successful_and_persists_outcome(self):
        result = StepResult(
            tool="http",
            action="http_probe",
            ok=False,
            payload={"findings": [{"status_code": None, "error": "[Errno 61] Connection refused"}]},
            error="connection refused",
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.outcome, NEGATIVE)
        self.assertEqual(result.payload["result_outcome"], NEGATIVE)

    def test_job_storage_keeps_negative_and_skipped_counts_separate_from_done(self):
        with tempfile.TemporaryDirectory() as tmp:
            jobs_root = Path(tmp)
            state = ShellState()
            handle_new("recon[target=example.com]", state, jobs_root=jobs_root, job_id="A12F", render_summary=False, announce_entry=False)
            append_job_result(
                "A12F",
                {"tool": "dns", "action": "dns", "ok": False, "error": "nxdomain", "payload": {"negative_observation": True}},
                jobs_root=jobs_root,
            )
            append_job_result(
                "A12F",
                {"tool": "fingerprint", "action": "web_fingerprint", "ok": True, "error": "", "payload": {"skipped": True}},
                jobs_root=jobs_root,
            )
            job = load_job("A12F", jobs_root)

        self.assertIsNotNone(job)
        assert job is not None
        self.assertEqual([step["outcome"] for step in job.steps], [NEGATIVE, SKIPPED])
        self.assertEqual(job.summary["negative_steps"], 1)
        self.assertEqual(job.summary["skipped_steps"], 1)
        self.assertEqual(job.status, "completed")


if __name__ == "__main__":
    unittest.main()
