import unittest

from blackline.core.recon.steps.port_scan import port_scan_step, port_state_counts
from blackline.core.recon.models import ReconTarget


class PortScanStepTests(unittest.TestCase):
    def test_port_scan_step_keeps_recon_facing_inputs(self):
        step = port_scan_step(
            ReconTarget(raw="10.0.0.1", target_type="ip", host="10.0.0.1"),
            {
                "strategy": "quiet",
                "speed": "high",
                "probe": "service",
                "top_ports": "20",
            },
        )

        self.assertEqual(step.name, "port_scan")
        self.assertEqual(step.tool, "nmap")
        self.assertEqual(step.inputs["target"], "10.0.0.1")
        self.assertEqual(step.inputs["strategy"], "quiet")
        self.assertEqual(step.inputs["speed"], "high")
        self.assertEqual(step.inputs["probe"], "service")
        self.assertEqual(step.inputs["top_ports"], "20")

    def test_port_state_counts_tracks_open_filtered_and_interesting(self):
        counts = port_state_counts(
            [
                {"port": 22, "protocol": "tcp", "state": "filtered", "service": "ssh"},
                {"port": 53, "protocol": "tcp", "state": "open", "service": "domain"},
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                {"port": 123, "protocol": "udp", "state": "closed", "service": "ntp"},
            ]
        )

        self.assertEqual(counts["open"], 2)
        self.assertEqual(counts["filtered"], 1)
        self.assertEqual(counts["interesting"], 3)


if __name__ == "__main__":
    unittest.main()
