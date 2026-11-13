import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import publish_release
import validate_awg_outputs
import validate_config

import build

ROOT = Path(__file__).resolve().parents[1]
COMPILER = ROOT / ".tools" / ("sing-box.exe" if os.name == "nt" else "sing-box")
COMMIT = "a" * 40


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("config", "scripts", "cache/sources", ".github/workflows"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / "requirements.txt").write_text("", encoding="utf-8")
        (self.root / ".github/workflows/build.yml").write_text("# fixture\n", encoding="utf-8")
        (self.root / "scripts/build.py").write_text("# fixture\n", encoding="utf-8")
        (self.root / "scripts/publish_release.py").write_text("# fixture\n", encoding="utf-8")

    def write_config(self, name, value):
        (self.root / "config" / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def cache_source(self, source, text):
        data = text.encode("utf-8")
        path = self.root / "cache/sources" / f"{source['id']}.data"
        path.write_bytes(data)
        metadata = {"id": source["id"], "url": source["url"], "sha256": hashlib.sha256(data).hexdigest(),
                    "fetched_at": "2026-11-13T00:00:00+00:00"}
        (self.root / "cache/sources" / f"{source['id']}.metadata.json").write_text(json.dumps(metadata), encoding="utf-8")

    def prepare_root(self):
        domain_source = {"id": "domains", "url": "https://example.com/domains.lst", "format": "suffix-lines",
                         "min_entries": 1000, "max_bytes": 1000000, "description": "fixture domains"}
        psl = {"id": "psl", "url": "https://example.com/psl.dat", "min_entries": 2,
               "max_bytes": 1000, "description": "fixture PSL"}
        service = {"id": "service", "service": "Fixture", "url": "https://example.com/service.txt",
                   "reference": "https://example.com", "description": "fixture service", "format": "cidr-lines",
                   "max_bytes": 1000, "min_entries": 2, "max_entries": 2,
                   "min_ipv4_entries": 1, "min_ipv6_entries": 1,
                   "min_ipv4_prefix_length": 20, "min_ipv6_prefix_length": 32,
                   "max_ipv4_addresses": 1000, "max_ipv6_addresses": 2 ** 100}
        registry = {"id": "registry", "url": "https://example.com/registry.txt", "format": "cidr-lines",
                    "min_entries": 1, "max_entries": 10, "max_bytes": 1000,
                    "min_ipv4_entries": 1, "min_ipv6_entries": 0,
                    "min_ipv4_prefix_length": 12, "min_ipv6_prefix_length": 32,
                    "max_ipv4_addresses": 1000, "max_ipv6_addresses": 2 ** 64,
                    "description": "fixture registry"}
        self.write_config("sources.json", {"sources": [domain_source], "core_excluded_sources": [],
                                           "public_suffix_list": psl})
        self.write_config("service-networks.json", {"schema_version": 1, "sources": [service],
                                                    "validation": {"max_drop_fraction": 0.25, "max_growth_fraction": 0.5}})
        self.write_config("registry-ip-sources.json", {"schema_version": 1, "sources": [registry]})
        self.write_config("manual-vpn.json", {"schema_version": 1, "rules": []})
        self.write_config("direct-exceptions.json", {"schema_version": 1, "rules": []})
        self.write_config("policy.json", {
            "schema_version": 1, "shared_roots": {}, "service_owned_suffixes": {},
            "validation": {"max_invalid_fraction": 0.01, "minimum_output_domains": 1000,
                           "max_source_drop_fraction": 0.2, "max_source_growth_fraction": 0.5,
                           "max_output_drop_fraction": 0.2, "max_output_growth_fraction": 0.5,
                           "max_previous_age_days": 7, "maximum_registry_ips": 100,
                           "max_service_stale_hours": 24,
                           "registry_ip": {"max_drop_fraction": 0.25, "max_growth_fraction": 0.5}},
        })
        self.write_config("probes.json", {"domains": ["blocked.example", "direct.example"],
                                          "expectations": {"blocked.example": "VPN", "direct.example": "Direct"}})
        self.write_config("monitoring.json", {"schema_version": 1,
                                              "provider": {"name": "fixture", "url": "https://example.com", "country": "RU",
                                                           "probes_per_target": 1, "timeout_seconds": 1},
                                              "targets": ["blocked.example"]})
        popularity = {"id": "tranco", "url": "https://example.com/top-1m.csv.zip", "archive": "zip",
                      "member": "top-1m.csv", "format": "tranco-csv", "max_bytes": 1000000,
                      "max_uncompressed_bytes": 1000000, "min_entries": 1, "description": "fixture popularity"}
        self.write_config("popularity.json", {"schema_version": 1, "max_domains": 100, "source": popularity})
        lock = json.loads((ROOT / "config/tools-lock.json").read_text(encoding="utf-8"))
        self.write_config("tools-lock.json", lock)
        domains = ["blocked.example"] + [f"domain{i}.example" for i in range(1000)]
        self.cache_source(domain_source, "\n".join(domains) + "\n")
        self.cache_source(psl, "com\norg\n")
        self.cache_source(service, "1.0.0.0/24\n2606:4700::/32\n")
        self.cache_source(registry, "1.1.1.2/32\n8.8.8.0/24\n")
        self.cache_source(popularity, "1,blocked.example\n2,popular.example\n")

    @unittest.skipUnless(COMPILER.is_file(), "pinned sing-box compiler is not installed")
    def test_offline_build_and_release_dry_run(self):
        self.prepare_root()
        output = self.root / "dist"
        args = argparse.Namespace(root=str(self.root), offline=True, fetch_only=False, previous=None,
                                  previous_rules=None, output=str(output), sing_box=str(COMPILER),
                                  max_workers=1, cache_max_age_days=30, cache_max_bytes=1024 ** 3)
        with patch.dict(os.environ, {"GITHUB_SHA": COMMIT, "GITHUB_REPOSITORY": "owner/Routing"}, clear=False):
            build.build(args)
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        self.assertTrue(manifest["offline_replay"])
        self.assertGreaterEqual(manifest["output"]["total_conditions"], 1000)
        for name in publish_release.DATASETS:
            self.assertTrue((output / f"{name}.srs").is_file())
        self.assertEqual(validate_awg_outputs.validate_outputs(output), {"catalog_datasets": 7, "presets": 4})
        import validate_outputs
        self.assertEqual(validate_outputs.validate_outputs(output, ROOT / "schemas" / "output"), [])
        verified = publish_release.verify_candidate(output, self.root, COMMIT, allow_initial_baseline=True, allow_offline=True)
        self.assertEqual(verified["environment"]["github_commit"], COMMIT)

        environment = dict(os.environ)
        environment.update({"GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push",
                            "GITHUB_REPOSITORY": "owner/Routing", "GITHUB_SHA": COMMIT,
                            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_TOKEN": "unused"})
        command = [sys.executable, str(ROOT / "scripts/publish_release.py"), "--input", str(output),
                   "--output", str(self.root / "release"), "--root", str(self.root), "--dry-run"]
        with patch.dict(os.environ, environment, clear=True):
            result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"status": "dry-run"', result.stderr)
        self.assertFalse((self.root / "release").exists())

    def test_real_configuration_schemas_and_rejection(self):
        self.assertEqual(validate_config.validate_all(ROOT), [])
        self.prepare_root()
        config_path = self.root / "config/manual-vpn.json"
        invalid = json.loads(config_path.read_text(encoding="utf-8"))
        invalid["rules"].append({"kind": "ip_cidr", "domain": "1.1.1.1/32", "reason": "not allowed"})
        config_path.write_text(json.dumps(invalid), encoding="utf-8")
        errors = validate_config.validate_all(self.root)
        self.assertTrue(any("manual-vpn.json" in error for error in errors))

    def test_shared_roots_require_a_direct_probe(self):
        check = validate_config.validate_shared_root_probes
        policy = {"shared_roots": {"cloudflare.com": "cdn", "pages.dev": "hosting"}}
        # A Direct probe for a subdomain covers the root.
        ok = {"expectations": {"ordinary-project.pages.dev": "Direct", "cloudflare.com": "Direct"}}
        self.assertEqual(check(policy, ok), [])
        # A VPN-routed or missing root is reported.
        missing = {"expectations": {"pages.dev": "Direct"}}
        errors = check(policy, missing)
        self.assertEqual(len(errors), 1)
        self.assertIn("cloudflare.com", errors[0])
        # The real repository configuration must satisfy the invariant.
        import json as _json
        real_policy = _json.loads((ROOT / "config/policy.json").read_text(encoding="utf-8"))
        real_probes = _json.loads((ROOT / "config/probes.json").read_text(encoding="utf-8"))
        self.assertEqual(check(real_policy, real_probes), [])

    def test_cache_is_pruned_by_age_and_size(self):
        cache = self.root / "cache/sources"
        old = cache / "old.data"
        old.write_bytes(b"12345")
        new = cache / "new.data"
        new.write_bytes(b"67890")
        now = 2_000_000_000
        os.utime(old, (now - 40 * 86400, now - 40 * 86400))
        os.utime(new, (now, now))
        result = build.prune_cache(cache, max_age_days=30, max_bytes=1024, now=now)
        self.assertEqual(result["removed_files"], 1)
        self.assertFalse(old.exists())
        os.utime(new, (now - 100, now - 100))
        result = build.prune_cache(cache, max_age_days=30, max_bytes=1, now=now)
        self.assertEqual(result["removed_files"], 1)
        self.assertFalse(new.exists())

    def test_public_package_api(self):
        package_root = str(ROOT)
        if package_root not in sys.path:
            sys.path.insert(0, package_root)
        import routing
        self.assertEqual(routing.normalize_domain("EXAMPLE.COM."), "example.com")
        self.assertTrue(issubclass(routing.BuildError, routing.RoutingError))
        self.assertTrue(issubclass(routing.PublishError, routing.RoutingError))
        self.assertTrue(issubclass(routing.ServiceNetworkError, routing.RoutingError))


if __name__ == "__main__":
    unittest.main()
