import datetime as dt
import ipaddress
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

    def test_public_ips_are_separate_and_malformed_records_are_classified(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "mixed.data"
            path.write_text("a.example\n1.1.1.1\n2606:4700:4700::1111\n10.0.0.1\n_bad.example\n1.1.1.1\n", encoding="utf-8")
            networks = set()
            exact, suffix, stats = build.parse_source(
                path, {"id": "fixture", "format": "suffix-lines", "min_entries": 1}, 1, networks)
        self.assertEqual({str(n) for n in networks}, {"1.1.1.1/32", "2606:4700:4700::1111/128"})
        self.assertEqual(suffix, {"a.example"})
        self.assertEqual(stats["ip_records"], 3)
        self.assertEqual(stats["ip_addresses"], 2)
        self.assertEqual(stats["duplicate_records"], 0)
        self.assertEqual(stats["invalid_by_reason"], {"non-public IP address": 1, "invalid DNS labels": 1})

    def test_tampered_offline_cache_is_refused_without_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / "fixture.data").write_bytes(b"tampered")
            build.write_json(path / "fixture.metadata.json", {"url": "https://example.com/data", "sha256": "0" * 64})
            with patch("urllib.request.build_opener", side_effect=AssertionError("network not permitted")):
                with self.assertRaises(build.BuildError):
                    build.fetch_source({"id": "fixture", "url": "https://example.com/data"}, path, offline=True)


class ManualAndDiffTests(unittest.TestCase):
    def test_manual_rules_require_reason_review_and_narrow_suffix(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manual.json"
            psl = build.PublicSuffixes("com\n")
            build.write_json(path, {"schema_version": 1, "rules": [
                {"kind": "domain_suffix", "domain": "Example.COM", "reason": "reviewed service", "review_after": "2027-01-01"}
            ]})
            exact, suffix, _, records = build.read_manual_rules(path, psl, require_review=True)
            self.assertFalse(exact)
            self.assertEqual(set(suffix), {"example.com"})
            self.assertEqual(records[0]["domain"], "example.com")
            for rule in [
                {"kind": "domain_suffix", "domain": "com", "reason": "too broad", "review_after": "2027-01-01"},
                {"kind": "domain", "domain": "example.com", "reason": "missing review"},
                {"kind": "domain", "domain": "example.com", "review_after": "2027-01-01"},
            ]:
                build.write_json(path, {"schema_version": 1, "rules": [rule]})
                with self.subTest(rule=rule), self.assertRaises(build.BuildError):
                    build.read_manual_rules(path, psl, require_review=True)

    def test_direct_ip_exceptions_are_exact_and_public(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "direct.json"
            psl = build.PublicSuffixes("com\n")
            build.write_json(path, {"schema_version": 1, "rules": [
                {"kind": "ip_cidr", "domain": "1.1.1.1/32", "reason": "direct resolver", "review_after": "2027-01-01"}
            ]})
            exact, suffix, networks, records = build.read_manual_rules(path, psl, require_review=True, allow_ip=True)
            self.assertFalse(exact)
            self.assertFalse(suffix)
            self.assertEqual({str(n) for n in networks}, {"1.1.1.1/32"})
            self.assertEqual(records[0]["domain"], "1.1.1.1/32")
            for value in ["10.0.0.0/8", "1.1.1.0/24"]:
                build.write_json(path, {"schema_version": 1, "rules": [
                    {"kind": "ip_cidr", "domain": value, "reason": "invalid", "review_after": "2027-01-01"}
                ]})
                with self.subTest(value=value), self.assertRaises(build.BuildError):
                    build.read_manual_rules(path, psl, require_review=True, allow_ip=True)

    def test_ip_is_rejected_for_vpn_and_expired_direct_rules_stop_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manual.json"
            psl = build.PublicSuffixes("com\n")
            rule = {"kind": "ip_cidr", "domain": "1.1.1.1/32", "reason": "test", "review_after": "2027-01-01"}
            build.write_json(path, {"schema_version": 1, "rules": [rule]})
            with self.assertRaisesRegex(build.BuildError, "only for Direct"):
                build.read_manual_rules(path, psl)
            with self.assertRaisesRegex(build.BuildError, "overdue"):
                build.read_manual_rules(path, psl, require_review=True, allow_ip=True,
                                        now=dt.date(2027, 1, 2))
            build.read_manual_rules(path, psl, require_review=True, allow_ip=True,
                                    now=dt.date(2027, 1, 1))

    def test_semantic_diff_distinguishes_minimization_from_lost_coverage(self):
        previous = {"version": 3, "rules": [{"domain": ["same.example", "old.other"],
                                             "domain_suffix": ["child.example"]}]}
        exact = {"same.example": 0, "new.example": 1}
        suffix = {"example": 1}
        diff = build.make_domain_diff(previous, exact, suffix, exact, suffix, [{"id": "manual"}])
        self.assertEqual(diff["total_added"], 2)
        self.assertEqual(diff["total_removed"], 2)
        self.assertEqual(diff["effective_removed"], 1)
        self.assertEqual(diff["effective_removed_sample"], ["old.other"])
        self.assertEqual(diff["effective_added"], 2)

    def test_exact_registry_ips_never_merge_into_subnets(self):
        networks = build.exact_networks([
            ipaddress.ip_network("1.1.1.1/32"), ipaddress.ip_network("1.1.1.2/32"),
            ipaddress.ip_network("1.1.1.1/32"), ipaddress.ip_network("2001:db8::1/128"),
        ])
        self.assertEqual({str(n) for n in networks}, {"1.1.1.1/32", "1.1.1.2/32", "2001:db8::1/128"})

    def test_registry_drift_uses_actual_addresses(self):
        policy = {"validation": {"registry_ip": {"max_drop_fraction": .25, "max_growth_fraction": .5}}}
        previous = {"registry_ip": {"output": {"prefixes": ["1.1.1.1/32", "8.8.8.8/32"]}}}
        current = [ipaddress.ip_network(value) for value in ("1.1.1.1/32", "8.8.8.8/32", "9.9.9.9/32")]
        self.assertEqual(build.validate_registry(previous, current, policy)["added"], 1)
        with self.assertRaises(build.BuildError):
            build.validate_registry(previous, [ipaddress.ip_network("1.1.1.1/32")], policy)

    def test_only_the_legacy_registry_layout_gets_a_new_baseline(self):
        policy = {"validation": {"registry_ip": {"max_drop_fraction": .25, "max_growth_fraction": .5}}}
        previous = {"registry_cidr": None, "registry_ip": {
            "sources": [{"id": "antifilter-full"}, {"id": "refilter"}],
            "output": {"prefixes": ["1.1.1.1/32"]},
        }}
        current = [ipaddress.ip_network(f"10.{index}.0.1/32") for index in range(100)]
        result = build.validate_registry(previous, current, policy)
        self.assertEqual(result["baseline"], "first-registry-build")
        previous["registry_ip"]["sources"].append({"id": "antifilter-ipresolve"})
        with self.assertRaises(build.BuildError):
            build.validate_registry(previous, current, policy)


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


class AWGPresetTests(unittest.TestCase):
    def test_vpn_presets_never_route_direct_exceptions_to_vpn(self):
        presets = build.make_presets("https://example.com/")["presets"]
        self.assertEqual({item["id"] for item in presets},
                         {"routing-full", "routing-compact", "routing-wide-cidr"})
        by_id = {item["id"]: {r["tag"] for r in item["engines"]["singbox"]["ruleSets"]} for item in presets}
        self.assertEqual(by_id["routing-full"], {"routing", "routing-services", "routing-registry-ip"})
        self.assertEqual(by_id["routing-compact"], {"routing-core", "routing-services", "routing-registry-ip"})
        self.assertEqual(by_id["routing-wide-cidr"], {"routing-registry-ip-cidr"})
        for preset in presets:
            engine = preset["engines"]["singbox"]
            self.assertEqual(engine["action"], "tunnel")
            self.assertNotIn("routing-direct-exceptions", {item["tag"] for item in engine["ruleSets"]})
            for rule_set in engine["ruleSets"]:
                self.assertTrue(rule_set["url"].startswith("https://example.com/"))
                self.assertTrue(rule_set["url"].endswith(".srs"))


if __name__ == "__main__":
    unittest.main()
