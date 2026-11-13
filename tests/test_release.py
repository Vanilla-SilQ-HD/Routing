import copy
import hashlib
import sys
import tempfile
import unittest
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from publish_release import (
    BUILD_FILES,
    DATASETS,
    EVIDENCE_FILES,
    RELEASE_FILES,
    CredentialSafeRedirect,
    PublishError,
    fingerprint,
    initial_baseline_allowed,
    json_bytes,
    parse_checksums,
    prepare_assets,
    publish,
    sha256,
    verify_candidate,
)

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

    def create_draft(self, tag, commit, title, body, prerelease=False):
        self.events.append("draft")
        self.tag = tag
        self.body = body
        self.prerelease = prerelease
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

    def publish(self, release_id, prerelease=False):
        self.events.append("publish")
        self.existing = {"draft": False, "prerelease": prerelease, "assets": copy.deepcopy(self.uploaded),
                         "tag_name": self.tag, "html_url": "https://github.com/owner/Routing/releases/tag/" + self.tag}
        return self.existing

    def delete_release(self, release_id, tag=None):
        self.events.append(f"delete:{release_id}")
        if tag:
            self.events.append(f"delete-tag:{tag}")
        return True


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        self.commit = "a" * 40
        recipe_files = {"config/tools-lock.json": json_bytes({"sing_box_version": "1.14.4", "source_format_version": 3}),
                        "config/policy.json": json_bytes({"validation": {"max_service_stale_hours": 24}}),
                        "config/registry-ip-sources.json": json_bytes({"sources": [{"id": "registry"}]}),
                        "scripts/build.py": b"# fixture", "scripts/publish_release.py": b"# fixture",
                        "requirements.txt": b"", ".github/workflows/build.yml": b"# fixture"}
        for name, data in recipe_files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for name in BUILD_FILES - {"manifest.json"}:
            (self.candidate / name).write_bytes(b"fixture " + name.encode())
        compiler = {"version": "sing-box version 1.14.4", "source_format_version": 3,
                    "roundtrip": "passed", "sing_box_check": "passed", "network_service_started": False}
        self.manifest = {
            "schema_version": 1, "built_at": "2026-11-06T12:00:00Z", "offline_replay": False,
            "environment": {"github_commit": self.commit},
            "configuration_sha256": {name: sha256(self.root / name) for name in recipe_files},
            "compiler": dict(compiler),
            "sources": [],
            "scope": {"domains_only": False, "personal_rules_included": False, "router_access": False,
                      "broad_ai_category_included": False, "ru_direct_category_included": False,
                      "ip_rules_included": True, "registry_ip_rules_included": True,
                      "direct_exceptions_included": True, "dns_configuration_included": False},
            "output": {"total_conditions": 3, "exact": 1, "suffix": 2,
                       "srs_bytes": (self.candidate / "blocked-domains.srs").stat().st_size,
                       "files": {name: sha256(self.candidate / name) for name in BUILD_FILES - {"manifest.json", "report.html"}}},
            "validation": {"baseline": "previous-successful-or-approved-manifest", "warnings": []},
            "domain_diff": {"added": 0, "removed": 0, "effective_added": 0, "effective_removed": 0},
            "service_networks": {
                "sources": [{"id": "telegram", "url": "https://core.telegram.org/resources/cidr.txt"}],
                "validation": {"baseline": "first-service-build", "warnings": []},
                "output": {"total_prefixes": 2, "ipv4_prefixes": 1, "ipv6_prefixes": 1,
                           "ipv4_addresses": 16384, "ipv6_addresses": 2 ** 80,
                           "srs_bytes": (self.candidate / "blocked-services-ip.srs").stat().st_size},
                "compiler": dict(compiler),
            },
            "registry_ip": {
                "sources": [{"id": "refilter", "ip_addresses": 1},
                            {"id": "registry", "url": "https://example.com/cidr.txt", "exact_prefixes": 1}],
                "validation": {"baseline": "first-registry-build", "warnings": []},
                "output": {"total_prefixes": 1, "ipv4_prefixes": 1, "ipv6_prefixes": 0,
                           "prefixes": ["1.1.1.1/32"],
                           "srs_bytes": (self.candidate / "blocked-registry-ip.srs").stat().st_size},
                "compiler": dict(compiler),
            },
            "core": {
                "output": {"total_conditions": 2, "exact": 1, "suffix": 1,
                           "source_ids": ["fixture"],
                           "srs_bytes": (self.candidate / "blocked-domains-core.srs").stat().st_size},
                "compiler": dict(compiler),
            },
            "registry_cidr": {
                "sources": [{"id": "registry", "url": "https://example.com/cidr.txt"}],
                "validation": {"baseline": "first-registry-build", "warnings": []},
                "output": {"total_prefixes": 1, "ipv4_prefixes": 1, "ipv6_prefixes": 0,
                           "prefixes": ["198.51.100.0/24"],
                           "srs_bytes": (self.candidate / "blocked-registry-ip-cidr.srs").stat().st_size},
                "compiler": dict(compiler),
            },
            "direct_exceptions": {
                "rules": [],
                "output": {"total_conditions": 0,
                           "srs_bytes": (self.candidate / "routing-direct-exceptions.srs").stat().st_size},
                "compiler": dict(compiler),
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
        for name in (dataset + ".srs" for dataset in DATASETS):
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

    def test_registry_source_provenance_is_required(self):
        self.manifest["registry_ip"]["sources"].pop()
        self.write_manifest()
        with self.assertRaisesRegex(PublishError, "provenance"):
            verify_candidate(self.candidate, self.root, self.commit)

    def test_stale_service_fallback_requires_complete_evidence(self):
        validation = self.manifest["service_networks"]["validation"]
        validation.update({"baseline": "previous-service-data-stale",
                           "restored_from_built_at": "2026-11-06T10:00:00+00:00",
                           "stale_hours": 2, "fetch_errors": {"telegram": "timeout"}})
        self.write_manifest()
        self.assertEqual(verify_candidate(self.candidate, self.root, self.commit), self.manifest)
        validation["fetch_errors"] = {}
        self.write_manifest()
        with self.assertRaises(PublishError):
            verify_candidate(self.candidate, self.root, self.commit)
        validation["fetch_errors"] = {"telegram": "timeout"}
        validation["stale_hours"] = 25
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
        with zipfile.ZipFile(self.assets / "routing-evidence.zip") as archive:
            self.assertEqual(archive.namelist(), EVIDENCE_FILES)
            for name in EVIDENCE_FILES:
                self.assertEqual(archive.read(name), (self.candidate / name).read_bytes())
                self.assertEqual(archive.getinfo(name).date_time, (1980, 1, 1, 0, 0, 0))
        self.assertEqual(sha256(self.assets / "routing-evidence.zip"), sha256(second / "routing-evidence.zip"))

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
        self.assertIn("Для DNS используйте только доменный набор", github.body)

    def test_upload_or_verification_failure_keeps_previous_release(self):
        for failure in ("fail_upload", "corrupt_download"):
            for name in (dataset + ".srs" for dataset in DATASETS):
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
        previous["dataset_srs_sha256"]["blocked-services-ip"] = "0" * 64
        github.stored[metadata_asset["id"]] = json_bytes(previous)
        with self.assertRaisesRegex(PublishError, "inconsistent binary metadata"):
            self.publish_to(github)

    def test_incomplete_unchanged_release_does_not_silently_pass(self):
        for name in ("routing-evidence.zip", "blocked-services-ip.srs", "blocked-services-ip.srs.sha256"):
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
    def test_failed_upload_rolls_back_the_draft(self):
        old = {"assets": [], "tag_name": "previous"}
        github = FakeGitHub(old)
        github.fail_upload = "blocked-domains.srs"
        with self.assertRaises(PublishError):
            self.publish_to(github)
        self.assertIn("delete:10", github.events)
        self.assertNotIn("publish", github.events)
        self.assertIs(github.existing, old)

    def test_empty_api_response_is_accepted_for_delete(self):
        from publish_release import GitHub

        class EmptyResponse:
            def read(self, _limit):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class FakeOpener:
            def open(self, request, timeout):
                return EmptyResponse()

        github = GitHub("owner/Routing", "token")
        github.opener = FakeOpener()
        self.assertIsNone(github.delete_release(10) and None)

    def test_retention_selection_protects_latest_drafts_and_newest(self):
        from publish_release import releases_to_prune
        releases = [{"id": i, "tag_name": f"rules-{i}", "draft": False,
                     "published_at": f"2026-11-{i:02d}T00:00:00Z"} for i in range(1, 9)]
        releases.append({"id": 99, "tag_name": "draft", "draft": True, "published_at": "2026-11-09T00:00:00Z"})
        prune = releases_to_prune(releases, latest_id=8, keep=5)
        self.assertEqual([r["id"] for r in prune], [2, 1])
        self.assertEqual(releases_to_prune(releases, latest_id=8, keep=50), [])
        self.assertEqual(releases_to_prune([], latest_id=None, keep=5), [])

    def test_only_project_tags_are_deleted(self):
        from publish_release import is_project_tag
        self.assertTrue(is_project_tag("v2026.11.13-43422576187-1"))
        self.assertTrue(is_project_tag("rules-43311687566-1"))
        for foreign in ("v1.0.0", "latest", "release-1", "v2026.11.13", "rules-x-y",
                        "v2026.11.13-43422576187-1; rm -rf /", "../v2026.11.13-1-1"):
            self.assertFalse(is_project_tag(foreign), foreign)

    def test_delete_release_also_deletes_project_tag_but_never_foreign(self):
        from publish_release import GitHub

        class EmptyResponse:
            def read(self, _limit):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class FakeOpener:
            def __init__(self):
                self.urls = []

            def open(self, request, timeout):
                self.urls.append((request.get_method(), request.full_url))
                return EmptyResponse()

        github = GitHub("owner/Routing", "token")
        opener = FakeOpener()
        github.opener = opener
        github.delete_release(10, "v2026.11.13-43422576187-1")
        methods = [method for method, _ in opener.urls]
        self.assertEqual(methods, ["DELETE", "DELETE"])
        self.assertIn("/git/refs/tags/v2026.11.13-43422576187-1", opener.urls[1][1])
        with self.assertRaises(PublishError):
            github.delete_release(11, "v1.0.0")

    def test_overdue_review_warning_does_not_block_but_other_warnings_do(self):
        # Advisory overdue-review warnings are tolerated on a normal baseline.
        self.manifest["validation"]["warnings"] = ["Direct exception review is overdue: 1.1.1.1/32 (2027-02-01)"]
        self.write_manifest()
        self.assertEqual(verify_candidate(self.candidate, self.root, self.commit), self.manifest)
        # Any other warning must still block publication.
        self.manifest["validation"]["warnings"].append("Unexpected source problem")
        self.write_manifest()
        with self.assertRaises(PublishError):
            verify_candidate(self.candidate, self.root, self.commit)

    def test_large_change_candidate_publishes_as_prerelease_not_latest(self):
        self.manifest["validation"] = {"baseline": "large-change-candidate",
                                       "warnings": ["Large coverage growth staged for review: 1000 -> 5000"]}
        self.write_manifest()
        # verify_candidate accepts the candidate baseline.
        self.assertEqual(verify_candidate(self.candidate, self.root, self.commit), self.manifest)
        github = FakeGitHub()
        result = self.publish_to(github, tag="candidate-2026.11.20-123-1")
        self.assertEqual(result["status"], "candidate")
        self.assertTrue(github.prerelease)
        self.assertIn("Candidate pre-release", github.body)
        self.assertTrue(result["release_url"])

    def test_candidate_baseline_requires_review_warning(self):
        self.manifest["validation"] = {"baseline": "large-change-candidate", "warnings": []}
        self.write_manifest()
        with self.assertRaises(PublishError):
            verify_candidate(self.candidate, self.root, self.commit)


if __name__ == "__main__":
    unittest.main()
