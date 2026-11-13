import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from report import make_report


class ReportTests(unittest.TestCase):
    def test_dashboard_is_self_contained_and_embeds_safe_data(self):
        compiler = {"version": "sing-box version 1.14.4", "sing_box_check": "passed"}
        manifest = {
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


if __name__ == "__main__":
    unittest.main()
