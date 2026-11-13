import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from explain import explain


def write_rules(path, domains=(), suffixes=()):
    rules = {}
    if domains:
        rules["domain"] = sorted(domains)
    if suffixes:
        rules["domain_suffix"] = sorted(suffixes)
    path.write_text(json.dumps({"version": 3, "rules": [rules] if rules else []}), encoding="utf-8")


class ExplainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        (self.dir / "manifest.json").write_text(json.dumps({
            "built_at": "2026-11-13T00:00:00+00:00", "sources": [],
            "direct_exceptions": {"rules": [{"domain": "ok.ru", "reason": "available in RU", "review_after": "2027-01-01"}]},
        }), encoding="utf-8")
        write_rules(self.dir / "blocked-domains.json", domains=["exact.example"], suffixes=["blocked.example"])
        write_rules(self.dir / "blocked-domains-core.json", domains=["exact.example"])
        write_rules(self.dir / "blocked-domains-smart.json", domains=["exact.example"], suffixes=["blocked.example"])
        write_rules(self.dir / "routing-direct-exceptions.json", domains=["ok.ru"])

    def test_vpn_by_exact_rule(self):
        result = explain(self.dir, "exact.example")
        self.assertEqual(result["decision"], "VPN")
        self.assertEqual(result["matched_rule"], "exact.example")
        self.assertEqual(result["compact"], "VPN")
        self.assertEqual(result["smart"], "VPN")

    def test_vpn_by_suffix_covers_subdomain(self):
        result = explain(self.dir, "deep.sub.blocked.example")
        self.assertEqual(result["decision"], "VPN")
        self.assertEqual(result["matched_rule"], "blocked.example")
        self.assertEqual(result["matched_type"], "domain_suffix")
        self.assertEqual(result["compact"], "not-covered")
        self.assertEqual(result["smart"], "VPN")

    def test_direct_exception_wins_over_vpn(self):
        result = explain(self.dir, "ok.ru")
        self.assertEqual(result["decision"], "Direct")
        self.assertEqual(result["reason"], "direct-exception")
        self.assertEqual(result["exception"]["reason"], "available in RU")
        self.assertEqual(result["exception"]["review_after"], "2027-01-01")

    def test_unrouted_domain_defaults_to_direct(self):
        result = explain(self.dir, "ordinary.example")
        self.assertEqual(result["decision"], "Direct")
        self.assertIn("no-rule-matches", result["reason"])

    def test_idna_input_is_normalized(self):
        write_rules(self.dir / "blocked-domains.json", domains=["xn--e1afmkfd.xn--p1ai"])
        result = explain(self.dir, "ПРИМЕР.РФ")
        self.assertEqual(result["domain"], "xn--e1afmkfd.xn--p1ai")


if __name__ == "__main__":
    unittest.main()
