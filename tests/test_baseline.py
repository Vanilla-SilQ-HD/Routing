import gzip
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from load_baseline import CredentialSafeRedirect, get, read_manifest_zip, restore_latest_rules

from build import BuildError


class BaselineArtifactTests(unittest.TestCase):
    def test_only_expected_manifest_is_read_without_extracting_paths(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("../../should-not-be-written", "untrusted")
            archive.writestr("manifest.json", json.dumps({"schema_version": 1}))
        self.assertEqual(read_manifest_zip(stream.getvalue()), {"schema_version": 1})

    def test_missing_or_duplicate_manifest_fails(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("different.json", "{}")
        with self.assertRaises(BuildError):
            read_manifest_zip(stream.getvalue())

    def test_expanded_registry_manifest_fits_the_baseline_limit(self):
        stream = io.BytesIO()
        manifest = {"schema_version": 1, "registry_ip": {"prefixes": ["1.1.1.1/32"] * 300000}}
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest))
        self.assertGreater(len(json.dumps(manifest)), 2 * 1024 * 1024)
        self.assertEqual(read_manifest_zip(stream.getvalue()), manifest)

    def test_token_is_removed_on_signed_storage_redirect(self):
        handler = CredentialSafeRedirect()
        request = urllib.request.Request("https://api.github.com/artifact", headers={"Authorization": "Bearer fixture-token"})
        redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://storage.example/file")
        self.assertIsNone(redirected.get_header("Authorization"))
        with self.assertRaises(BuildError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://storage.example/file")


    def test_binary_download_uses_octet_stream_accept_header(self):
        with patch("load_baseline.urllib.request.build_opener") as factory:
            response = factory.return_value.open.return_value.__enter__.return_value
            response.read.return_value = b"{}"
            get("https://api.github.com/repos/owner/Routing/releases/assets/7", "token",
                as_json=False, octet_stream=True)
            asset_request = factory.return_value.open.call_args.args[0]
            get("https://api.github.com/repos/owner/Routing/actions/artifacts/7/zip", "token", as_json=False)
            artifact_request = factory.return_value.open.call_args.args[0]
        self.assertEqual(asset_request.get_header("Accept"), "application/octet-stream")
        self.assertEqual(artifact_request.get_header("Accept"), "application/vnd.github+json")

    def test_previous_rules_are_restored_from_the_latest_release(self):
        rules = b'{"version":3,"rules":[{"domain":["example.com"]}]}\n'
        payload = gzip.compress(rules, mtime=0)
        latest = {"tag_name": "rules-1-1", "assets": [{"id": 7, "name": "blocked-domains.json.gz"}]}
        def fake_get(url, token, as_json=True, limit=0, octet_stream=False):
            return latest if as_json else payload
        with tempfile.TemporaryDirectory() as temporary:
            previous_cwd = os.getcwd()
            try:
                os.chdir(temporary)
                with patch("load_baseline.get", side_effect=fake_get):
                    restore_latest_rules("https://api.github.com/repos/owner/Routing", "token")
                self.assertEqual(Path("previous/blocked-domains.json").read_bytes(), rules)
            finally:
                os.chdir(previous_cwd)


    def test_previous_rules_are_restored_from_evidence_zip(self):
        rules = b'{"version":3,"rules":[{"domain":["example.com"]}]}\n'
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("blocked-domains.json", rules)
        payload = stream.getvalue()
        latest = {"tag_name": "rules-2-1", "assets": [{"id": 8, "name": "routing-evidence.zip"}]}
        def fake_get(url, token, as_json=True, limit=0, octet_stream=False):
            return latest if as_json else payload
        with tempfile.TemporaryDirectory() as temporary:
            previous_cwd = os.getcwd()
            try:
                os.chdir(temporary)
                with patch("load_baseline.get", side_effect=fake_get):
                    restore_latest_rules("https://api.github.com/repos/owner/Routing", "token")
                self.assertEqual(Path("previous/blocked-domains.json").read_bytes(), rules)
            finally:
                os.chdir(previous_cwd)
    def test_get_rejects_credentials_outside_github_api(self):
        with self.assertRaises(BuildError):
            get("https://example.com/repos/owner/Routing", "token")

    def test_get_enforces_the_response_size_limit(self):
        with patch("load_baseline.urllib.request.build_opener") as factory:
            response = factory.return_value.open.return_value.__enter__.return_value
            response.read.return_value = b"x" * 101
            with self.assertRaises(BuildError):
                get("https://api.github.com/repos/owner/Routing", "token", limit=100)

    def test_missing_latest_release_is_a_noop(self):
        error = urllib.error.HTTPError("https://api.github.com/x", 404, "Not Found", {}, None)
        with patch("load_baseline.get", side_effect=error):
            self.assertIsNone(restore_latest_rules("https://api.github.com/repos/owner/Routing", "token"))

    def test_release_without_rule_assets_is_a_noop(self):
        with patch("load_baseline.get", return_value={"tag_name": "rules-1-1", "assets": []}):
            self.assertIsNone(restore_latest_rules("https://api.github.com/repos/owner/Routing", "token"))

    def test_reset_baseline_requires_an_explicit_manual_run(self):
        from load_baseline import main
        with patch.dict(os.environ, {"RESET_BASELINE": "true", "GITHUB_EVENT_NAME": "schedule"}, clear=True), self.assertRaises(BuildError):
            main()
        with patch.dict(os.environ, {"RESET_BASELINE": "true", "GITHUB_EVENT_NAME": "workflow_dispatch"}, clear=True):
            self.assertIsNone(main())

    def test_invalid_repository_is_rejected(self):
        from load_baseline import main
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "bad/name!", "BASELINE_BRANCH": "main",
                                     "GITHUB_TOKEN": "token"}, clear=True), self.assertRaises(BuildError):
            main()


if __name__ == "__main__":
    unittest.main()
