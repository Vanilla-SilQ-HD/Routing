import copy
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from publish_release import (BUILD_FILES, RELEASE_FILES, CredentialSafeRedirect, PublishError,
                             fingerprint, initial_baseline_allowed, json_bytes, parse_checksums, prepare_assets, publish,
                             sha256, verify_candidate)
from build import validate_previous


class FakeGitHub:
    repository = "owner/Routing"

    def __init__(self, existing=None):
        self.existing = existing
        self.events, self.stored, self.uploaded = [], {}, []
        self.fail_upload, self.corrupt_download = None, None

    def latest(self):
        self.events.append("latest")
        return self.existing

    def create_draft(self, tag, commit, title, body):
        self.events.append("draft")
        self.tag = tag
        self.body = body
        self.uploaded = []
        return {"id": 10, "draft": True}

    def upload(self, release_id, path):
        self.events.append("upload:" + path.name)
        if path.name == self.fail_upload:
            raise PublishError("Simulated upload failure")
        data = path.read_bytes()
        asset = {"id": len(self.stored) + 1, "state": "uploaded", "size": len(data), "name": path.name,
                 "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
        self.stored[asset["id"]] = data
        self.uploaded.append(asset)
        return asset

    def download(self, asset, limit=None):
        self.events.append("download:" + asset["name"])
        return b"corrupted" if asset["name"] == self.corrupt_download else self.stored[asset["id"]]

    def publish(self, release_id):
        self.events.append("publish")
        self.existing = {"draft": False, "prerelease": False, "assets": copy.deepcopy(self.uploaded),
                         "tag_name": self.tag, "html_url": "https://github.com/owner/Routing/releases/tag/" + self.tag}
        return self.existing


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        self.commit = "a" * 40
        recipe_files = {"config/tools-lock.json": json_bytes({"sing_box_version": "1.14.4", "source_format_version": 3}),
                        "scripts/build.py": b"# fixture", "scripts/publish_release.py": b"# fixture",
                        "requirements.txt": b"", ".github/workflows/build.yml": b"# fixture"}
        for name, data in recipe_files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for name in BUILD_FILES - {"manifest.json"}:
            (self.candidate / name).write_bytes(b"fixture " + name.encode())
        self.manifest = {
            "schema_version": 1, "built_at": "2026-11-06T12:00:00Z", "offline_replay": False,
            "environment": {"github_commit": self.commit},
            "configuration_sha256": {name: sha256(self.root / name) for name in recipe_files},
            "compiler": {"version": "sing-box version 1.14.4", "source_format_version": 3,
                         "roundtrip": "passed", "sing_box_check": "passed", "network_service_started": False},
            "scope": {"domains_only": False, "personal_rules_included": False, "router_access": False,
                      "broad_ai_category_included": False, "ru_direct_category_included": False,
                      "ip_rules_included": True, "dns_configuration_included": False},
            "output": {"total_conditions": 3, "srs_bytes": (self.candidate / "blocked-domains.srs").stat().st_size,
                       "files": {name: sha256(self.candidate / name) for name in BUILD_FILES - {"manifest.json", "report.html"}}},
            "validation": {"baseline": "previous-successful-or-approved-manifest", "warnings": []},
            "service_networks": {
                "sources": [{"id": "telegram", "url": "https://core.telegram.org/resources/cidr.txt"}],
                "validation": {"baseline": "first-service-build", "warnings": []},
                "output": {"total_prefixes": 2, "ipv4_prefixes": 1, "ipv6_prefixes": 1,
                           "ipv4_addresses": 16384, "ipv6_addresses": 2 ** 80,
                           "srs_bytes": (self.candidate / "blocked-services-ip.srs").stat().st_size},
                "compiler": {"version": "sing-box version 1.14.4", "source_format_version": 3,
                             "roundtrip": "passed", "sing_box_check": "passed", "network_service_started": False},
            },
        }
        self.write_manifest()
        self.assets = self.root / "release"
        self.metadata = prepare_assets(self.candidate, self.assets, self.manifest, "owner/Routing", "123", "1")

    def write_manifest(self):
        (self.candidate / "manifest.json").write_bytes(json_bytes(self.manifest))
        checksums = "".join(f"{sha256(self.candidate / name)}  {name}\n" for name in sorted(BUILD_FILES))
        (self.candidate / "SHA256SUMS").write_bytes(checksums.encode("ascii"))

    def publish_to(self, github, tag="rules-123-1"):
        return publish(self.assets, self.manifest, self.metadata, github, tag)

    def test_candidate_integrity_and_recipe(self):
        self.assertEqual(verify_candidate(self.candidate, self.root, self.commit), self.manifest)
        with self.assertRaises(PublishError):
            verify_candidate(self.candidate, self.root, "b" * 40)
        (self.root / "scripts/build.py").write_bytes(b"changed recipe")
        with self.assertRaises(PublishError):
            verify_candidate(self.candidate, self.root, self.commit)

    def test_corrupted_binary_fails_before_publication(self):
        for name in ("blocked-domains.srs", "blocked-services-ip.srs"):
            with self.subTest(name=name):
                path = self.candidate / name
                original = path.read_bytes()
                path.write_bytes(b"bad transfer")
                with self.assertRaisesRegex(PublishError, "checksum mismatch"):
                    verify_candidate(self.candidate, self.root, self.commit)
                path.write_bytes(original)

    def test_missing_service_binary_fails_before_publication(self):
        (self.candidate / "blocked-services-ip.srs").unlink()
        with self.assertRaisesRegex(PublishError, "artifact inventory"):
            verify_candidate(self.candidate, self.root, self.commit)

    def test_first_service_artifact_keeps_existing_domain_baseline(self):
        self.assertEqual(verify_candidate(self.candidate, self.root, self.commit,
                                         allow_initial_baseline=False), self.manifest)
        self.manifest["service_networks"]["validation"]["baseline"] = "previous-service-build"
        self.write_manifest()
        self.assertEqual(verify_candidate(self.candidate, self.root, self.commit), self.manifest)

    def test_service_evidence_and_counts_must_be_complete_and_valid(self):
        original = copy.deepcopy(self.manifest)
        failures = [
            ("output", "total_prefixes", 0), ("output", "ipv4_prefixes", 0),
            ("output", "ipv6_prefixes", 0), ("output", "ipv4_addresses", 0),
            ("output", "ipv6_addresses", 0), ("output", "ipv6_addresses", True),
            ("output", "total_prefixes", 99), ("output", "srs_bytes", 1),
            ("compiler", "roundtrip", "failed"), ("compiler", "sing_box_check", "failed"),
            ("compiler", "version", "sing-box version 1.0"),
            ("compiler", "network_service_started", True),
            ("validation", "baseline", "first-build"), ("validation", "warnings", ["review"]),
        ]
        for section, key, value in failures:
            with self.subTest(section=section, key=key, value=value):
                self.manifest = copy.deepcopy(original)
                self.manifest["service_networks"][section][key] = value
                self.write_manifest()
                with self.assertRaises(PublishError):
                    verify_candidate(self.candidate, self.root, self.commit)
        for section in (None, "sources", "compiler", "output", "validation"):
            with self.subTest(missing=section):
                self.manifest = copy.deepcopy(original)
                if section is None:
                    del self.manifest["service_networks"]
                else:
                    del self.manifest["service_networks"][section]
                self.write_manifest()
                with self.assertRaises(PublishError):
                    verify_candidate(self.candidate, self.root, self.commit)

    def test_first_build_can_publish_to_a_new_repository(self):
        self.manifest["validation"] = validate_previous(None, [], 3, {})
        self.write_manifest()
        allowed = initial_baseline_allowed(None, False, "workflow_dispatch")
        self.assertEqual(verify_candidate(self.candidate, self.root, self.commit,
                                         allow_initial_baseline=allowed), self.manifest)

    def test_existing_release_cannot_silently_lose_its_baseline(self):
        self.manifest["validation"] = validate_previous(None, [], 3, {})
        self.write_manifest()
        allowed = initial_baseline_allowed({"id": 10}, False, "schedule")
        with self.assertRaises(PublishError):
            verify_candidate(self.candidate, self.root, self.commit, allow_initial_baseline=allowed)

    def test_explicit_manual_reset_can_publish_but_unexpected_warnings_still_fail(self):
        self.manifest["validation"] = validate_previous(None, [], 3, {})
        self.write_manifest()
        allowed = initial_baseline_allowed({"id": 10}, True, "workflow_dispatch")
        self.assertEqual(verify_candidate(self.candidate, self.root, self.commit,
                                         allow_initial_baseline=allowed), self.manifest)
        self.manifest["validation"]["warnings"].append("Unexpected source problem")
        self.write_manifest()
        with self.assertRaises(PublishError):
            verify_candidate(self.candidate, self.root, self.commit, allow_initial_baseline=allowed)
        with self.assertRaises(PublishError):
            initial_baseline_allowed({"id": 10}, True, "schedule")

    def test_unsafe_or_unvalidated_build_cannot_be_published(self):
        original = copy.deepcopy(self.manifest)
        for section, key, value in [("scope", "router_access", True), ("compiler", "roundtrip", "failed"),
                                    ("output", "srs_bytes", 0), ("validation", "warnings", ["review"]),
                                    (None, "offline_replay", True)]:
            with self.subTest(key=key):
                self.manifest = copy.deepcopy(original)
                target = self.manifest[section] if section else self.manifest
                target[key] = value
                self.write_manifest()
                with self.assertRaises(PublishError):
                    verify_candidate(self.candidate, self.root, self.commit)

    def test_checksum_inventory_rejects_traversal_duplicates_and_omissions(self):
        digest = "0" * 64
        for text in [f"{digest}  ../secret\n", f"{digest}  file\n{digest}  file\n", ""]:
            with self.subTest(text=text), self.assertRaises(PublishError):
                parse_checksums(text, {"file"})

    def test_release_assets_have_exact_checksums_and_reproducible_source(self):
        self.assertEqual({p.name for p in self.assets.iterdir()}, RELEASE_FILES)
        checksums = parse_checksums((self.assets / "SHA256SUMS").read_text(), RELEASE_FILES - {"SHA256SUMS"})
        self.assertTrue(all(sha256(self.assets / name) == digest for name, digest in checksums.items()))
        second = self.root / "second-release"
        prepare_assets(self.candidate, second, self.manifest, "owner/Routing", "124", "1")
        for name in ("blocked-domains", "blocked-services-ip"):
            with gzip.open(self.assets / (name + ".json.gz"), "rb") as source:
                self.assertEqual(source.read(), (self.candidate / (name + ".json")).read_bytes())
            self.assertEqual(sha256(self.assets / (name + ".json.gz")), sha256(second / (name + ".json.gz")))

    def test_fingerprint_ignores_time_but_tracks_binary_and_recipe(self):
        changed = copy.deepcopy(self.manifest)
        changed["built_at"] = "2026-11-07T12:00:00Z"
        self.assertEqual(fingerprint(changed), fingerprint(self.manifest))
        changed["configuration_sha256"]["scripts/build.py"] = "0" * 64
        self.assertNotEqual(fingerprint(changed), fingerprint(self.manifest))
        changed = copy.deepcopy(self.manifest)
        changed["output"]["files"]["blocked-domains.srs"] = "1" * 64
        self.assertNotEqual(fingerprint(changed), fingerprint(self.manifest))
        changed = copy.deepcopy(self.manifest)
        changed["output"]["files"]["blocked-services-ip.srs"] = "2" * 64
        self.assertNotEqual(fingerprint(changed), fingerprint(self.manifest))

    def test_only_service_binary_change_creates_a_new_release(self):
        github = FakeGitHub()
        self.publish_to(github)
        previous_fingerprint = self.metadata["fingerprint"]
        previous_domain_hash = self.metadata["srs_sha256"]
        path = self.candidate / "blocked-services-ip.srs"
        path.write_bytes(b"new app networks")
        self.manifest["output"]["files"][path.name] = sha256(path)
        self.manifest["service_networks"]["output"]["srs_bytes"] = path.stat().st_size
        self.write_manifest()
        self.assets = self.root / "next-release"
        self.metadata = prepare_assets(self.candidate, self.assets, self.manifest, "owner/Routing", "124", "1")
        self.assertEqual(self.metadata["srs_sha256"], previous_domain_hash)
        self.assertNotEqual(self.metadata["fingerprint"], previous_fingerprint)
        github.events.clear()
        self.assertEqual(self.publish_to(github, "rules-124-1")["status"], "published")
        self.assertIn("draft", github.events)

    def test_previous_domain_only_release_is_upgraded_without_resetting_domains(self):
        github = FakeGitHub()
        self.publish_to(github)
        metadata_asset = next(a for a in github.existing["assets"] if a["name"] == "release.json")
        previous = copy.deepcopy(self.metadata)
        previous["fingerprint"] = hashlib.sha256(json_bytes({
            "schema_version": 1, "srs_sha256": previous["srs_sha256"],
            "configuration_sha256": self.manifest["configuration_sha256"],
        })).hexdigest()
        del previous["service_srs_sha256"]
        github.stored[metadata_asset["id"]] = json_bytes(previous)
        github.existing["assets"] = [a for a in github.existing["assets"] if not a["name"].startswith("blocked-services-ip")]
        github.events.clear()
        self.assertEqual(self.publish_to(github, "rules-124-1")["status"], "published")
        self.assertIn("draft", github.events)

    def test_publish_only_after_every_draft_asset_is_downloaded_and_verified(self):
        github = FakeGitHub()
        self.assertEqual(self.publish_to(github)["status"], "published")
        self.assertEqual(github.events[:2], ["latest", "draft"])
        self.assertEqual(github.events[-1], "publish")
        self.assertEqual(sum(e.startswith("download:") for e in github.events), len(RELEASE_FILES))
        self.assertIn("blocked-services-ip.srs", github.body)
        self.assertIn("для DNS-правил используйте только доменный набор", github.body)

    def test_upload_or_verification_failure_keeps_previous_release(self):
        for failure in ("fail_upload", "corrupt_download"):
            for name in ("blocked-domains.srs", "blocked-services-ip.srs"):
                with self.subTest(failure=failure, name=name):
                    old = {"assets": [], "tag_name": "previous"}
                    github = FakeGitHub(old)
                    setattr(github, failure, name)
                    with self.assertRaises(PublishError):
                        self.publish_to(github)
                    self.assertIs(github.existing, old)
                    self.assertNotIn("publish", github.events)

    def test_unchanged_result_is_verified_without_creating_another_release(self):
        github = FakeGitHub()
        self.publish_to(github)
        github.events.clear()
        self.assertEqual(self.publish_to(github, "rules-124-1")["status"], "unchanged")
        self.assertNotIn("draft", github.events)
        self.assertNotIn("publish", github.events)
        self.assertIn("download:blocked-domains.srs", github.events)
        self.assertIn("download:blocked-services-ip.srs", github.events)
        for name in ("blocked-domains.srs", "blocked-services-ip.srs", "blocked-services-ip.srs.sha256"):
            with self.subTest(name=name):
                github.corrupt_download = name
                with self.assertRaises(PublishError):
                    self.publish_to(github)

    def test_unchanged_release_rejects_inconsistent_service_hash_metadata(self):
        github = FakeGitHub()
        self.publish_to(github)
        metadata_asset = next(a for a in github.existing["assets"] if a["name"] == "release.json")
        previous = copy.deepcopy(self.metadata)
        previous["service_srs_sha256"] = "0" * 64
        github.stored[metadata_asset["id"]] = json_bytes(previous)
        with self.assertRaisesRegex(PublishError, "inconsistent binary metadata"):
            self.publish_to(github)

    def test_incomplete_unchanged_release_does_not_silently_pass(self):
        for name in ("report.html", "blocked-services-ip.srs", "blocked-services-ip.srs.sha256"):
            with self.subTest(name=name):
                github = FakeGitHub()
                self.publish_to(github)
                github.existing["assets"] = [a for a in github.existing["assets"] if a["name"] != name]
                with self.assertRaises(PublishError):
                    self.publish_to(github)

    def test_redirect_drops_credentials_and_rejects_http(self):
        handler = CredentialSafeRedirect()
        request = urllib.request.Request("https://api.github.com/asset", headers={"Authorization": "Bearer fixture-token"})
        redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://release-assets.githubusercontent.com/file")
        self.assertIsNone(redirected.get_header("Authorization"))
        with self.assertRaises(PublishError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://example.com/file")


if __name__ == "__main__":
    unittest.main()
