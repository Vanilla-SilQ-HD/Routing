import io
import json
import sys
import unittest
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build import BuildError
from load_baseline import CredentialSafeRedirect, read_manifest_zip


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


if __name__ == "__main__":
    unittest.main()
