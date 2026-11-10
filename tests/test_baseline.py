import gzip
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build import BuildError
from load_baseline import CredentialSafeRedirect, read_manifest_zip, restore_latest_rules


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

    def test_token_is_removed_on_signed_storage_redirect(self):
        handler = CredentialSafeRedirect()
        request = urllib.request.Request("https://api.github.com/artifact", headers={"Authorization": "Bearer fixture-token"})
        redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://storage.example/file")
        self.assertIsNone(redirected.get_header("Authorization"))
        with self.assertRaises(BuildError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://storage.example/file")


    def test_previous_rules_are_restored_from_the_latest_release(self):
        rules = b'{"version":3,"rules":[{"domain":["example.com"]}]}\n'
        payload = gzip.compress(rules, mtime=0)
        latest = {"tag_name": "rules-1-1", "assets": [{"id": 7, "name": "blocked-domains.json.gz"}]}
        def fake_get(url, token, as_json=True, limit=0):
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


if __name__ == "__main__":
    unittest.main()
