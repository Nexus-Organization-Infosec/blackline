import unittest

from blackline.core.recon.models import InvalidReconTargetError, ReconTarget, normalize_recon_target
from blackline.core.recon.pipeline import ReconPipeline, build_recon_pipeline


class ReconPipelineTests(unittest.TestCase):
    def test_normalize_target_detects_ip(self):
        target = normalize_recon_target("10.0.0.1")

        self.assertEqual(
            target,
            ReconTarget(raw="10.0.0.1", target_type="ip", host="10.0.0.1"),
        )

    def test_normalize_target_detects_domain(self):
        target = normalize_recon_target("Example.COM")

        self.assertEqual(
            target,
            ReconTarget(raw="Example.COM", target_type="domain", host="example.com"),
        )

    def test_normalize_target_detects_url(self):
        target = normalize_recon_target("https://Example.com:8443/login?q=1")

        self.assertEqual(
            target,
            ReconTarget(
                raw="https://Example.com:8443/login?q=1",
                target_type="url",
                host="example.com",
                scheme="https",
                path="/login?q=1",
                port="8443",
            ),
        )

    def test_build_recon_pipeline_is_deterministic_for_same_input(self):
        first = build_recon_pipeline("https://example.com/path")
        second = build_recon_pipeline("https://example.com/path")

        self.assertEqual(first, second)
        self.assertEqual([step.name for step in first.steps], ["http_probe", "web_fingerprint", "dns", "ipintel", "tls_inspection", "rdap", "port_scan"])
        self.assertEqual(first, ReconPipeline(target=second.target, steps=second.steps))

    def test_ip_pipeline_order(self):
        pipeline = build_recon_pipeline("10.0.0.1")

        self.assertEqual(
            [step.name for step in pipeline.steps],
            ["reverse_dns", "ipintel", "http_ip_probe", "web_fingerprint", "tls_inspection", "rdap", "port_scan"],
        )

    def test_domain_pipeline_order(self):
        pipeline = build_recon_pipeline("example.com")

        self.assertEqual(
            [step.name for step in pipeline.steps],
            ["dns", "ipintel", "http_probe", "web_fingerprint", "tls_inspection", "rdap", "port_scan"],
        )

    def test_url_pipeline_order(self):
        pipeline = build_recon_pipeline("https://example.com/login")

        self.assertEqual(
            [step.name for step in pipeline.steps],
            ["http_probe", "web_fingerprint", "dns", "ipintel", "tls_inspection", "rdap", "port_scan"],
        )

    def test_http_url_does_not_assume_tls(self):
        pipeline = build_recon_pipeline("http://example.com/login")

        self.assertNotIn("tls_inspection", [step.name for step in pipeline.steps])

    def test_surface_profile_excludes_network_intel_and_active_port_scan(self):
        pipeline = build_recon_pipeline("example.com", params={"strategy": "surface"})

        self.assertEqual(
            [step.name for step in pipeline.steps],
            ["dns", "http_probe", "web_fingerprint", "tls_inspection", "rdap"],
        )

    def test_balanced_and_deep_keep_the_full_evidence_set(self):
        balanced = build_recon_pipeline("example.com", params={"strategy": "balanced"})
        deep = build_recon_pipeline("example.com", params={"strategy": "deep"})

        self.assertEqual([step.tool for step in balanced.steps], [step.tool for step in deep.steps])
        self.assertIn("nmap", [step.tool for step in deep.steps])

    def test_fast_is_a_compatibility_alias_for_surface(self):
        fast = build_recon_pipeline("example.com", params={"strategy": "fast"})

        self.assertNotIn("nmap", [step.tool for step in fast.steps])
        self.assertNotIn("ipintel", [step.tool for step in fast.steps])

    def test_normalize_target_rejects_malformed_target(self):
        with self.assertRaises(InvalidReconTargetError):
            normalize_recon_target("bad target")

        with self.assertRaises(InvalidReconTargetError):
            normalize_recon_target("http:///missing-host")

        with self.assertRaises(InvalidReconTargetError):
            normalize_recon_target("999.999.999.999")


if __name__ == "__main__":
    unittest.main()
