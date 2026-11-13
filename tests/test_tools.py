import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import install_tools
import measure_memory
import publish_release
import validate_awg_outputs


class FakeResponse:
    def __init__(self, data, url="https://github.com/compiler.tar.gz"):
        self.data = data
        self.url = url

    def read(self, _limit):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class ToolTests(unittest.TestCase):
    def make_archive(self, executable=b"compiler"):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            info = tarfile.TarInfo("sing-box")
            info.size = len(executable)
            archive.addfile(info, io.BytesIO(executable))
        return stream.getvalue()

    def test_compiler_is_installed_only_after_hash_verification(self):
        data = self.make_archive()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "config").mkdir()
            lock = {"sing_box_version": "1.14.4", "assets": {"linux-amd64": {
                "url": "https://github.com/compiler.tar.gz", "sha256": hashlib.sha256(data).hexdigest(), "member": "sing-box"}}}
            (root / "config/tools-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            with patch.object(install_tools, "ROOT", root), \
                    patch("install_tools.platform.system", return_value="linux"), \
                    patch("install_tools.platform.machine", return_value="x86_64"), \
                    patch("install_tools.urllib.request.urlopen", return_value=FakeResponse(data)):
                install_tools.main()
            self.assertEqual((root / ".tools/sing-box").read_bytes(), b"compiler")
            with patch.object(install_tools, "ROOT", root), \
                    patch("install_tools.platform.system", return_value="linux"), \
                    patch("install_tools.platform.machine", return_value="x86_64"), \
                    patch("install_tools.urllib.request.urlopen", return_value=FakeResponse(data + b"corrupt")), self.assertRaises(SystemExit):
                install_tools.main()

    def test_linux_rss_is_read_from_proc(self):
        process = type("Process", (), {"pid": 123})()
        with patch("measure_memory.os.name", "posix"), \
                patch("measure_memory.Path.read_text", return_value="Name:\tsing-box\nVmRSS:\t  456 kB\n"):
            self.assertEqual(measure_memory.rss_bytes(process), 456 * 1024)

    def test_awg_output_validation_rejects_bad_presets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "catalog.json").write_text(json.dumps({"sources": [
                {"id": "routing", "url": "https://example.com/{}", "names": sorted(validate_awg_outputs.EXPECTED_DATASETS)}
            ]}), encoding="utf-8")
            (root / "presets.user.json").write_text(json.dumps({"presets": []}), encoding="utf-8")
            with self.assertRaises(validate_awg_outputs.AWGOutputError):
                validate_awg_outputs.validate_outputs(root)

    def test_previous_release_tag_is_recorded_in_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.mkdir()
            for name in publish_release.BUILD_FILES:
                (candidate / name).write_bytes(b"fixture")
            manifest = {"built_at": "2026-11-13T00:00:00+00:00",
                        "configuration_sha256": {},
                        "environment": {"github_commit": "a" * 40},
                        "output": {"files": {name + ".srs": "0" * 64 for name in publish_release.DATASETS}}}
            metadata = publish_release.prepare_assets(candidate, root / "release", manifest, "owner/Routing", "1", "1",
                                                     previous_release_tag="rules-old")
            self.assertEqual(metadata["previous_release_tag"], "rules-old")
            saved = json.loads((root / "release/release.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["previous_release_tag"], "rules-old")


if __name__ == "__main__":
    unittest.main()
