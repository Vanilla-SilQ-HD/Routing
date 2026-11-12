import argparse
import copy
import datetime as dt
import ipaddress
import json
import random
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build
from service_networks import (
    ServiceNetworkError,
    coverage,
    normalize_networks,
    parse_networks,
    parse_ripe_source,
    prepare_services,
    restore_services,
    validate_previous_services,
)

TELEGRAM = """91.108.56.0/22
91.108.4.0/22
91.108.8.0/22
91.108.16.0/22
91.108.12.0/22
149.154.160.0/20
91.105.192.0/23
91.108.20.0/22
185.76.151.0/24
2001:b28:f23d::/48
2001:b28:f23f::/48
2001:67c:4e8::/48
2001:b28:f23c::/48
2a0a:f280::/32
"""


class ServiceNetworkTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / "config/service-networks.json").read_text())
        self.source = self.config["sources"][0]
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.input = Path(self.temp.name) / "cidr.txt"

    def parse(self, text=TELEGRAM):
        self.input.write_text(text, encoding="utf-8")
        return parse_networks(self.input, self.source)

    def test_telegram_native_ip_and_ipv6_are_covered_without_domains(self):
        networks, stats = self.parse()
        self.assertEqual(stats["unique_conditions"], 14)
        self.assertEqual(stats["total_prefixes"], 11)
        self.assertEqual(len(stats["raw_prefixes"]), 14)
        for value in ["149.154.167.41", "91.108.8.1", "2001:b28:f23d::1", "2a0a:f280::1"]:
            ip = ipaddress.ip_address(value)
            self.assertTrue(any(ip in n for n in networks if ip.version == n.version), value)
        # Public resolvers, nearby IPs and saved router exceptions are outside it.
        for value in ["1.1.1.1", "8.8.8.8", "91.108.3.255", "149.154.176.1",
                      "92.255.48.21", "82.204.183.100", "10.10.8.1", "79.182.46.20",
                      "2.26.124.137", "150.241.87.13", "31.76.240.200", "2001:b28:f23e::1"]:
            ip = ipaddress.ip_address(value)
            self.assertFalse(any(ip in n for n in networks if ip.version == n.version), value)

    def test_every_invalid_or_nonpublic_line_stops_the_whole_source(self):
        for line in ["<html>upstream error</html>", "not-a-cidr", "91.108.8.1/22", "1.1.1.1",
                     "0.0.0.0/0", "::/0", "10.0.0.0/24", "127.0.0.0/24", "169.254.0.0/24",
                     "192.0.2.0/24", "192.0.0.0/20", "224.0.0.0/24", "ff00::/8", "fc00::/64", "fe80::/64",
                     "2001:db8::/48", "8.0.0.0/8"]:
            with self.subTest(line=line), self.assertRaises(ServiceNetworkError):
                self.parse(TELEGRAM + line + "\n")

    def test_empty_source_and_lost_ip_family_fail(self):
        for text in ["", "# comments only\n", "\n".join(x for x in TELEGRAM.splitlines() if ":" not in x),
                     "\n".join(x for x in TELEGRAM.splitlines() if ":" in x)]:
            with self.subTest(text=text), self.assertRaises(ServiceNetworkError):
                self.parse(text)

    def test_duplicates_do_not_expand_coverage_or_hide_missing_entries(self):
        networks, stats = self.parse(TELEGRAM + TELEGRAM)
        self.assertEqual(stats["duplicate_records"], 14)
        self.assertEqual(networks, self.parse()[0])
        with self.assertRaises(ServiceNetworkError):
            self.parse("149.154.160.0/20\n" * 20)

    def test_minimization_preserves_exact_address_coverage(self):
        rng = random.Random(24011)
        original = [ipaddress.ip_network(f"91.108.{n}.0/24") for n in range(32) if rng.random() < .7]
        original += [ipaddress.ip_network(f"2001:b28:f23d:{n:x}::/64") for n in range(32) if rng.random() < .7]
        merged = normalize_networks(original)
        self.assertEqual(coverage(original), coverage(merged))
        # Check both boundaries and adjacent addresses; gap-filling would fail.
        for n in original:
            for address in [n.network_address - 1, n.network_address, n.broadcast_address, n.broadcast_address + 1]:
                self.assertEqual(any(address in x for x in original if x.version == address.version),
                                 any(address in x for x in merged if x.version == address.version))

    def test_normalization_keeps_both_families_from_an_iterator(self):
        values = [ipaddress.ip_network("91.108.4.0/22"), ipaddress.ip_network("2001:b28:f23d::/48")]
        self.assertEqual(normalize_networks(iter(values)), values)

    def test_fixed_address_space_limits_stop_unexpected_growth(self):
        self.source["max_ipv4_addresses"] = 1
        with self.assertRaisesRegex(ServiceNetworkError, "address-space limit"):
            self.parse()

    def baseline(self):
        _, stats = self.parse()
        source = dict(stats, id=self.source["id"], url=self.source["url"])
        return {"service_networks": {"sources": [source]}}, [source]

    def test_upgrade_from_domain_only_manifest_preserves_domain_baseline(self):
        old = {"sources": [{"id": "domain-source"}]}
        self.assertEqual(validate_previous_services(old, [], self.config["validation"]),
                         {"baseline": "first-service-build", "warnings": []})
        self.assertNotIn("service_networks", old)

    def test_unchanged_service_coverage_passes_its_own_baseline(self):
        old, current = self.baseline()
        self.assertEqual(validate_previous_services(old, current, self.config["validation"])["baseline"],
                         "previous-service-build")

    def test_same_count_coverage_replacement_and_source_url_change_fail(self):
        old, current = self.baseline()
        for replacements in [{"prefixes": ["8.8.0.0/16", "2606:4700::/32"]},
                             {"url": "https://different.example/list"}, {"id": "new-source"}]:
            changed = copy.deepcopy(current)
            changed[0].update(replacements)
            with self.subTest(change=replacements), self.assertRaises(ServiceNetworkError):
                validate_previous_services(old, changed, self.config["validation"])

    def test_lost_ipv6_does_not_hide_behind_unchanged_ipv4(self):
        old, current = self.baseline()
        current = copy.deepcopy(current)
        current[0]["prefixes"] = [n for n in current[0]["prefixes"] if ":" not in n]
        with self.assertRaises(ServiceNetworkError):
            validate_previous_services(old, current, self.config["validation"])

    def test_required_service_download_failure_never_creates_partial_output(self):
        output = Path(self.temp.name) / "not-published"
        args = argparse.Namespace(root=str(ROOT), offline=False, fetch_only=False,
                                  previous=None, output=str(output), sing_box=None)
        def fetch(source, *unused):
            if source["id"] == "telegram-networks":
                raise build.BuildError("Required service feed failed")
            return self.input, {}
        with patch.object(build, "fetch_source", side_effect=fetch), self.assertRaisesRegex(build.BuildError, "Required service"):
            build.build(args)
        self.assertFalse(output.exists())

    def test_bad_service_data_stops_before_domain_processing_or_publication(self):
        self.input.write_text("<html>error</html>")
        output = Path(self.temp.name) / "not-published"
        args = argparse.Namespace(root=str(ROOT), offline=False, fetch_only=False,
                                  previous=None, output=str(output), sing_box=None)
        with patch.object(build, "fetch_source", return_value=(self.input, {})), self.assertRaises(ServiceNetworkError):
            build.build(args)
        self.assertFalse(output.exists())

    def ripe_fixture(self, mutate=None):
        source = next(s for s in self.config["sources"] if s.get("asn") == 62041)
        prefixes = {"v4": {"originating": ["149.154.160.0/20", "95.161.64.0/20"]},
                    "v6": {"originating": ["2001:67c:4e8::/48"]}}
        data = {"status": "ok", "data": {"resource": "62041", "types": ["o"], "af": ["v4", "v6"],
                "list_prefixes": True, "query_time": "2026-11-06T08:00:00", "prefixes": prefixes,
                "counts": {"v4": {"originating": 2}, "v6": {"originating": 1}}}}
        identity = {"status": "ok", "data": {"resource": "62041", "holder": source["expected_holder"],
                    "announced": True, "query_endtime": "2026-11-06T08:00:00"}}
        if mutate:
            mutate(data, identity)
        prefix_path = Path(self.temp.name) / "ripe-prefixes.json"
        identity_path = Path(self.temp.name) / "ripe-identity.json"
        prefix_path.write_text(json.dumps(data))
        identity_path.write_text(json.dumps(identity))
        meta = {"fetched_at": "2026-11-06T12:00:00+00:00"}
        fetched = {source["id"]: (prefix_path, dict(meta)),
                   source["identity_source"]["id"]: (identity_path, dict(meta))}
        return source, fetched

    def test_ripe_adds_confirmed_telegram_infrastructure_beyond_operator_feed(self):
        source, fetched = self.ripe_fixture()
        self.input.write_text(TELEGRAM)
        fetched[self.source["id"]] = (self.input, {"id": self.source["id"], "url": self.source["url"]})
        config = dict(self.config, sources=[self.source, source])
        networks, manifest = prepare_services(fetched, config, None)
        self.assertTrue(any(ipaddress.ip_address("95.161.64.1") in n for n in networks if n.version == 4))
        self.assertFalse(any(ipaddress.ip_address("95.161.80.1") in n for n in networks if n.version == 4))
        self.assertEqual(manifest["output"]["ipv4_addresses"], self.parse()[1]["ipv4_addresses"] + 4096)
        self.assertIn("identity", manifest["sources"][1])

    def test_ripe_identity_resource_status_freshness_and_inventory_are_required(self):
        mutations = [lambda d,i: i["data"].update(holder="Unrelated cloud provider"),
                     lambda d,i: i["data"].update(resource="12345"),
                     lambda d,i: i["data"].update(announced=False),
                     lambda d,i: d["data"].update(resource="12345"),
                     lambda d,i: d.update(status="error"),
                     lambda d,i: d["data"].update(types=["t"]),
                     lambda d,i: d["data"].update(query_time="2026-11-01T08:00:00"),
                     lambda d,i: i["data"].update(query_endtime="2026-11-01T08:00:00"),
                     lambda d,i: d["data"]["counts"]["v4"].update(originating=20),
                     lambda d,i: d["data"]["prefixes"]["v4"].update(originating=["8.0.0.0/8", "95.161.64.0/20"])]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)), self.assertRaises(ServiceNetworkError):
                source, fetched = self.ripe_fixture(mutate)
                parse_ripe_source(source, fetched)


    def test_stale_fallback_restores_only_a_complete_fresh_service_set(self):
        _, stats = self.parse()
        now = dt.datetime.now(dt.UTC)
        previous = {"built_at": now.isoformat(), "service_networks": {
            "sources": [dict(self.source, **stats)]
        }}
        config = {"sources": [self.source]}
        networks, manifest = restore_services(previous, config, 24, now=now)
        self.assertEqual(networks, self.parse()[0])
        self.assertEqual(manifest["validation"]["baseline"], "previous-service-data-stale")
        self.assertEqual(manifest["output"]["total_prefixes"], stats["total_prefixes"])
        old = dict(previous, built_at="2000-01-01T00:00:00+00:00")
        with self.assertRaises(ServiceNetworkError):
            restore_services(old, config, 24, now=now)
        changed = {"sources": [dict(self.source, url="https://example.com/changed.txt")]}
        with self.assertRaises(ServiceNetworkError):
            restore_services(previous, changed, 24, now=now)
        with self.assertRaises(ServiceNetworkError):
            restore_services(None, config, 24, now=now)


if __name__ == "__main__":
    unittest.main()
