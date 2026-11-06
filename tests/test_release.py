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
                             fingerprint, json_bytes, parse_checksums, prepare_assets, publish,
                             sha256, verify_candidate)


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
            "scope": {"domains_only": True, "personal_rules_included": False, "router_access": False,
                      "broad_ai_category_included": False, "ru_direct_category_included": False,
                      "ip_rules_included": False, "dns_configuration_included": False},
            "output": {"total_conditions": 3, "srs_bytes": (self.candidate / "blocked-domains.srs").stat().st_size,
                       "files": {name: sha256(self.candidate / name) for name in BUILD_FILES - {"manifest.json", "report.html"}}},
            "validation": {"warnings": []},
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
        (self.candidate / "blocked-domains.srs").write_bytes(b"bad transfer")
        with self.assertRaisesRegex(PublishError, "checksum mismatch"):
            verify_candidate(self.candidate, self.root, self.commit)

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
        with gzip.open(self.assets / "blocked-domains.json.gz", "rb") as source:
            self.assertEqual(source.read(), (self.candidate / "blocked-domains.json").read_bytes())
        second = self.root / "second-release"
        prepare_assets(self.candidate, second, self.manifest, "owner/Routing", "124", "1")
        self.assertEqual(sha256(self.assets / "blocked-domains.json.gz"), sha256(second / "blocked-domains.json.gz"))

    def test_fingerprint_ignores_time_but_tracks_binary_and_recipe(self):
        changed = copy.deepcopy(self.manifest)
        changed["built_at"] = "2026-11-07T12:00:00Z"
        self.assertEqual(fingerprint(changed), fingerprint(self.manifest))
        changed["configuration_sha256"]["scripts/build.py"] = "0" * 64
        self.assertNotEqual(fingerprint(changed), fingerprint(self.manifest))
        changed = copy.deepcopy(self.manifest)
        changed["output"]["files"]["blocked-domains.srs"] = "1" * 64
        self.assertNotEqual(fingerprint(changed), fingerprint(self.manifest))

    def test_publish_only_after_every_draft_asset_is_downloaded_and_verified(self):
        github = FakeGitHub()
        self.assertEqual(self.publish_to(github)["status"], "published")
        self.assertEqual(github.events[:2], ["latest", "draft"])
        self.assertEqual(github.events[-1], "publish")
        self.assertEqual(sum(e.startswith("download:") for e in github.events), len(RELEASE_FILES))

    def test_upload_or_verification_failure_keeps_previous_release(self):
        for failure in ("fail_upload", "corrupt_download"):
            with self.subTest(failure=failure):
                old = {"assets": [], "tag_name": "previous"}
                github = FakeGitHub(old)
                setattr(github, failure, "blocked-domains.srs")
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
        github.corrupt_download = "blocked-domains.srs"
        with self.assertRaises(PublishError):
            self.publish_to(github)

    def test_incomplete_unchanged_release_does_not_silently_pass(self):
        github = FakeGitHub()
        self.publish_to(github)
        github.existing["assets"] = [a for a in github.existing["assets"] if a["name"] != "report.html"]
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
