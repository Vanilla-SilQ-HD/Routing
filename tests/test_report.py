import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from report import make_report


class ReportTests(unittest.TestCase):
    def _manifest(self):
        compiler = {"version": "sing-box version 1.14.4", "sing_box_check": "passed"}
        return {
            "built_at": "2026-11-10T00:00:00+00:00",
            "environment": {"github_commit": "a" * 40, "repository": "owner/Routing"},
            "output": {"total_conditions": 2, "exact": 1, "suffix": 1, "srs_bytes": 100,
                       "files": {name: "0" * 64 for name in (
                           "blocked-domains.srs", "blocked-domains-core.srs", "blocked-domains-smart.srs",
                           "blocked-services-ip.srs",
                           "blocked-registry-ip.srs", "blocked-registry-ip-cidr.srs",
                           "routing-direct-exceptions.srs")}},
            "sources": [{"id": "source", "url": "https://example.com/source", "unique_conditions": 2,
                         "ip_addresses": 1, "invalid": 0, "filtered_conditions": 0, "sha256": "0" * 64}],
            "service_networks": {
                "validation": {"baseline": "previous-service-build"},
                "output": {"total_prefixes": 1, "srs_bytes": 50},
                "sources": [{"service": "Telegram", "url": "https://example.com/cidr",
                             "ipv4_prefixes": 1, "ipv6_prefixes": 0}],
            },
            "core": {"output": {"total_conditions": 1, "srs_bytes": 40},
                     "compiler": compiler},
            "smart": {"output": {"total_conditions": 1, "srs_bytes": 41},
                      "compiler": compiler},
            "registry_cidr": {"validation": {"baseline": "previous-registry-build"},
                              "output": {"total_prefixes": 1, "srs_bytes": 30, "prefixes": ["198.51.100.0/24"]},
                              "compiler": compiler},
            "registry_ip": {"validation": {"baseline": "previous-registry-build"},
                            "output": {"total_prefixes": 1, "srs_bytes": 25, "prefixes": ["1.1.1.1/32"]}},
            "direct_exceptions": {"output": {"total_conditions": 0, "srs_bytes": 17}},
            "domain_diff": {"added": 1, "removed": 0, "effective_added": 1, "effective_removed": 0},
            "domain_changes": {"total_added": 1, "total_removed": 0,
                               "effective_added": 1, "effective_removed": 0,
                               "by_kind": {"domain": {"added_sample": ["new.example"], "removed_sample": []}},
                               "effective_removed_sample": []},
            "validation": {"baseline": "previous-successful-or-approved-manifest"},
            "compiler": compiler,
            "scope": {"router_access": False},
        }

    def test_dashboard_is_self_contained_and_embeds_safe_data(self):
        manifest = self._manifest()
        probes = [{"domain": "new.example", "base_decision": "VPN", "final_decision": "VPN",
                   "expected": "VPN", "matched_rule": "new.example", "sources": ["source"]}]
        exclusions = [{"domain": "x</script>", "kind": "domain_suffix",
                       "reason": "public suffix", "sources": ["source"]}]
        report = make_report(manifest, exclusions, probes)
        self.assertIn("Routing Dashboard", report)
        self.assertIn("window.ROUTING_DATA=", report)
        self.assertIn("new.example", report)
        self.assertIn("https://github.com/owner/Routing/releases/latest/download/blocked-domains.srs", report)
        self.assertNotIn("<script src=", report)
        self.assertNotIn("x</script><script>", report)
        self.assertIn("x<\\/script>", report)
        self.assertIn("pageSize=250", report)
        self.assertIn("paginatedNetwork('registry'", report)
        self.assertIn("registry-search", report)
        self.assertNotIn("D.registry.prefixes.map", report)
        self.assertIn("Content-Security-Policy", report)
        self.assertIn("default-src 'none'", report)
        self.assertIn("safeUrl", report)
        # URLs must go through the https-only escaper, never raw interpolation.
        self.assertIn('safeUrl(x.url)', report)
        self.assertIn('safeUrl(s.url)', report)
        self.assertNotIn('href="${s.url}"', report)
        self.assertNotIn('href="${x.url}"', report)

    def test_golden_payload_structure(self):
        # Golden test: the embedded ROUTING_DATA payload has a stable, documented shape.
        import json
        report = make_report(self._manifest(), [], [])
        payload = report.split("window.ROUTING_DATA=", 1)[1].split(";</script>", 1)[0]
        data = json.loads(payload.replace("<\\/", "</"))
        self.assertEqual(set(data), {"meta", "summary", "downloads", "sources", "probes",
                                     "changes", "exclusions", "services", "registry",
                                     "registryCidr", "directRulesList", "validation"})
        self.assertEqual(data["summary"]["domains"], 2)
        self.assertEqual(data["summary"]["smartDomains"], 1)
        self.assertEqual(len(data["downloads"]), 7)
        titles = [d["title"] for d in data["downloads"]]
        self.assertIn("Домены · Smart", titles)
        for download in data["downloads"]:
            self.assertTrue(download["url"].startswith("https://"))
            self.assertTrue(download["url"].endswith(".srs"))
            self.assertEqual(len(download["sha256"]), 64)

    def test_xss_payload_in_source_and_domain_is_escaped(self):
        manifest = self._manifest()
        manifest["sources"][0]["id"] = "<script>alert(1)</script>"
        manifest["sources"][0]["url"] = "https://example.com/?x=<script>"
        probes = [{"domain": "<img src=x onerror=alert(1)>", "base_decision": "VPN",
                   "final_decision": "VPN", "expected": "VPN", "matched_rule": "x", "sources": ["s"]}]
        report = make_report(manifest, [], probes)
        # The raw closing-script breakout must never appear unescaped in the document.
        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertIn("<\\/script>", report)


if __name__ == "__main__":
    unittest.main()
