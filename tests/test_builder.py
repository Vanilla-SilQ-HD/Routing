import datetime as dt
import json
import random
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build


class DomainSemanticsTests(unittest.TestCase):
    def test_normalization_is_idna2008_and_preserves_labels(self):
        self.assertEqual(build.normalize_domain(" Faß.DE. "), "xn--fa-hia.de")
        self.assertEqual(build.normalize_domain("ПРИМЕР.РФ"), "xn--e1afmkfd.xn--p1ai")
        self.assertEqual(build.normalize_domain("WWW.Example.com"), "www.example.com")

    def test_urls_ips_invalid_wildcards_and_injection_are_rejected(self):
        for value in ["https://a.example", "1.1.1.1", "a.example/path", "a.example:443", "*.example", "-bad.example", "a..example", "a.example..", "a@example.com", "a\n.example", "<script>", ""]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                build.normalize_domain(value)

    def test_psl_private_wildcard_exception_and_unknown_single_label(self):
        psl = build.PublicSuffixes("com\nco.uk\npages.dev\n*.ck\n!www.ck\n")
        for domain in ["com", "co.uk", "pages.dev", "a.ck", "unknown-tld"]:
            self.assertTrue(psl.is_public_suffix(domain), domain)
        for domain in ["service.pages.dev", "example.com", "www.ck", "a.www.ck", "a.b.ck"]:
            self.assertFalse(psl.is_public_suffix(domain), domain)

    def test_filtering_a_parent_preserves_explicit_blocked_child(self):
        psl = build.PublicSuffixes("com\npages.dev\n")
        shared = {"googleapis.com": "shared"}
        candidates = {"googleapis.com": 1, "generativelanguage.googleapis.com": 1, "pages.dev": 1, "blocked.pages.dev": 1}
        kept = {name: mask for name, mask in candidates.items() if not build.exclusion_reason("domain_suffix", name, shared, psl)}
        exact, suffix = build.minimize({}, kept)
        self.assertTrue(build.match_rule("generativelanguage.googleapis.com", exact, suffix))
        self.assertTrue(build.match_rule("child.blocked.pages.dev", exact, suffix))
        self.assertFalse(build.match_rule("fonts.googleapis.com", exact, suffix))
        self.assertFalse(build.match_rule("ordinary.pages.dev", exact, suffix))

    def test_exact_names_never_expand_to_children(self):
        exact, suffix = build.minimize({"exact.example": 1, "child.suffix.example": 2}, {"suffix.example": 1, "child.suffix.example": 2})
        self.assertEqual(exact, {"exact.example": 1})
        self.assertTrue(build.match_rule("exact.example", exact, suffix))
        self.assertFalse(build.match_rule("child.exact.example", exact, suffix))
        self.assertTrue(build.match_rule("deep.child.suffix.example", exact, suffix))
        self.assertFalse(build.match_rule("not-suffix.example", exact, suffix))

    def test_private_wildcard_does_not_remove_individual_tenants(self):
        psl = build.PublicSuffixes("com\n*.ck\n// ===BEGIN PRIVATE DOMAINS===\n*.eth.limo\n")
        self.assertTrue(psl.is_broad_routing_suffix("eth.limo"))
        self.assertFalse(psl.is_broad_routing_suffix("blocked-tenant.eth.limo"))
        self.assertTrue(psl.is_broad_routing_suffix("a.ck"))

    def test_service_owned_psl_exceptions_only_preserve_existing_rules(self):
        psl = build.PublicSuffixes("com\n// ===BEGIN PRIVATE DOMAINS===\nclaudeusercontent.com\nframe.claudeusercontent.com\npages.dev\n")
        service_owned = {"claudeusercontent.com"}
        self.assertIsNone(build.exclusion_reason("domain_suffix", "claudeusercontent.com", {}, psl, service_owned))
        self.assertIsNone(build.exclusion_reason("domain_suffix", "frame.claudeusercontent.com", {}, psl, service_owned))
        self.assertIsNotNone(build.exclusion_reason("domain_suffix", "pages.dev", {}, psl, service_owned))
        self.assertIsNotNone(build.exclusion_reason("domain_suffix", "claudeusercontent.com", {"claudeusercontent.com": "shared"}, psl, service_owned))

    def test_minimization_preserves_membership_for_generated_corpus(self):
        rng = random.Random(58136)
        domains = {".".join([rng.choice(["a", "b", "c", "d"]) for _ in range(rng.randint(1, 4))] + ["example"]) for _ in range(1000)}
        exact = {name: 1 for name in sorted(domains) if rng.random() < 0.4}
        suffix = {name: 2 for name in sorted(domains) if rng.random() < 0.3}
        small_exact, small_suffix = build.minimize(exact, suffix)
        probes = domains | {"x." + name for name in domains} | {"not" + name for name in domains}
        for name in probes:
            self.assertEqual(bool(build.match_rule(name, exact, suffix)), bool(build.match_rule(name, small_exact, small_suffix)), name)


class InputFailureTests(unittest.TestCase):
    def parse(self, data, fmt="singbox-domains", invalid_fraction=0):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input"
            path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
            return build.parse_source(path, {"id": "fixture", "format": fmt, "min_entries": 1}, invalid_fraction)

    def test_singbox_exact_and_suffix_are_kept_distinct(self):
        exact, suffix, _ = self.parse({"version": 3, "rules": [{"domain": ["a.example"], "domain_suffix": ["b.example"]}]})
        self.assertEqual(exact, {"a.example"})
        self.assertEqual(suffix, {"b.example"})

    def test_logical_ip_and_port_rules_are_never_silently_flattened(self):
        for rule in [{"ip_cidr": ["1.1.1.1/32"]}, {"domain_suffix": ["a.example"], "port": [443]}, {"type": "logical", "mode": "or", "rules": []}, {}, {"domain_suffix": []}]:
            with self.subTest(rule=rule), self.assertRaises(build.BuildError):
                self.parse({"version": 3, "rules": [rule]})

    def test_empty_and_html_sources_stop_build(self):
        for content in ["", "<html>maintenance</html>", "good.example\n<script>alert(1)</script>"]:
            with self.subTest(content=content), self.assertRaises(build.BuildError):
                self.parse(content, "suffix-lines")

    def test_supported_line_prefixes_and_duplicate_accounting(self):
        exact, suffix, stats = self.parse("# comment\n*.a.example\n.b.example\na.example.\n", "suffix-lines")
        self.assertFalse(exact)
        self.assertEqual(suffix, {"a.example", "b.example"})
        self.assertEqual(stats["duplicate_records"], 1)

    def test_tampered_offline_cache_is_refused_without_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / "fixture.data").write_bytes(b"tampered")
            build.write_json(path / "fixture.metadata.json", {"url": "https://example.com/data", "sha256": "0" * 64})
            with patch("urllib.request.build_opener", side_effect=AssertionError("network not permitted")):
                with self.assertRaises(build.BuildError):
                    build.fetch_source({"id": "fixture", "url": "https://example.com/data"}, path, offline=True)


class BaselineGuardTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 11, 6, tzinfo=dt.timezone.utc)
        self.policy = {"validation": {"max_previous_age_days": 7, "max_source_drop_fraction": .2, "max_source_growth_fraction": .5, "max_output_drop_fraction": .2, "max_output_growth_fraction": .5}}
        self.previous = {"schema_version": 1, "built_at": self.now.isoformat(), "sources": [{"id": "a", "unique_conditions": 1000}], "output": {"total_conditions": 1000}}

    def validate(self, count=1001, stats=None, previous=None):
        return build.validate_previous(previous or self.previous, stats or [{"id": "a", "unique_conditions": count}], count, self.policy, self.now)

    def test_normal_update_passes(self):
        self.assertEqual(self.validate()["warnings"], [])

    def test_source_loss_growth_and_output_loss_stop_update(self):
        for count in [0, 100, 799, 1501, 1000000]:
            with self.subTest(count=count), self.assertRaises(build.BuildError):
                self.validate(count)
        with self.assertRaises(build.BuildError):
            self.validate(700, [{"id": "a", "unique_conditions": 1000}])

    def test_missing_source_or_stale_baseline_requires_review(self):
        with self.assertRaises(build.BuildError):
            self.validate(stats=[{"id": "new", "unique_conditions": 1000}])
        old = dict(self.previous, built_at=(self.now - dt.timedelta(days=8)).isoformat())
        with self.assertRaises(build.BuildError):
            self.validate(previous=old)

    def test_no_previous_version_is_explicit_bootstrap(self):
        result = build.validate_previous(None, [], 1000, self.policy, self.now)
        self.assertEqual(result["baseline"], "first-build")
        self.assertTrue(result["warnings"])


if __name__ == "__main__":
    unittest.main()
