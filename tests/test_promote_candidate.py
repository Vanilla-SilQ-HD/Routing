import contextlib
import io
import json
import os
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch


class Response:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self):
        return json.dumps(self.data).encode()


class PromoteCandidateTests(unittest.TestCase):
    def run_workflow(self, tag, prerelease=True):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/promote_candidate.yml").read_text(encoding="utf-8")
        script = workflow.split("          python - <<'PY'\n", 1)[1].split("\n          PY", 1)[0]
        script = "\n".join(line[10:] for line in script.splitlines())
        calls = []

        def open_request(request, timeout):
            calls.append((request.get_method(), request.full_url, json.loads(request.data) if request.data else None))
            if request.get_method() == "GET":
                return Response({"id": 42, "prerelease": prerelease})
            return Response({"tag_name": tag, "html_url": "https://example.org/release"})

        with (
            patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo", "GITHUB_TOKEN": "test", "TAG": tag}),
            patch.object(urllib.request, "build_opener") as build_opener,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            build_opener.return_value.open.side_effect = open_request
            try:
                exec(compile(script, "promote_candidate.yml", "exec"), {})
            except SystemExit as error:
                return calls, str(error)
        return calls, None

    def test_promotes_without_changing_tag_or_assets(self):
        tag = "candidate-2026.11.20-123-1"
        calls, error = self.run_workflow(tag)
        self.assertIsNone(error)
        self.assertEqual(
            calls,
            [
                ("GET", f"https://api.github.com/repos/owner/repo/releases/tags/{tag}", None),
                ("PATCH", "https://api.github.com/repos/owner/repo/releases/42", {"prerelease": False, "make_latest": "true"}),
            ],
        )

    def test_rejects_non_candidate_tag(self):
        calls, error = self.run_workflow("v1")
        self.assertEqual(calls, [])
        self.assertIn("Refusing to promote", error)

    def test_rejects_stable_release(self):
        calls, error = self.run_workflow("candidate-2026.11.20-123-1", prerelease=False)
        self.assertEqual(len(calls), 1)
        self.assertIn("not a pre-release", error)
