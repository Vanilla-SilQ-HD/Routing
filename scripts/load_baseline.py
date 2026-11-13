"""Restore only the manifest of a successful build from this repository/branch.

GitHub read-only APIs only. No publication and no router access.
"""
import gzip
import io
import json
import logging
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

if str(Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routing.net import CredentialSafeRedirect

try:
    from .build import BuildError, write_json
    from .logging_utils import configure_logging
except ImportError:
    from logging_utils import configure_logging  # type: ignore[no-redef]

    from build import BuildError, write_json  # type: ignore[no-redef]

logger = logging.getLogger(__name__)


def get(url: str, token: str, as_json: bool = True, limit: int = 4 * 1024 * 1024, octet_stream: bool = False) -> Any:
    if urllib.parse.urlsplit(url).hostname != "api.github.com":
        raise BuildError("Credentials may only be sent to api.github.com")
    request = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token, "User-Agent": "selective-vpn-rules/1",
        "Accept": "application/octet-stream" if octet_stream else "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    opener = urllib.request.build_opener(CredentialSafeRedirect())
    with opener.open(request, timeout=120) as response:
        payload = response.read(limit + 1)
        if len(payload) > limit:
            raise BuildError("Baseline response exceeds size limit")
    return json.loads(payload) if as_json else payload


def read_manifest_zip(payload: bytes) -> Any:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = [m for m in archive.infolist() if m.filename == "manifest.json"]
        if len(members) != 1 or members[0].file_size > 64 * 1024 * 1024:
            raise BuildError("Unexpected baseline artifact")
        return json.loads(archive.read(members[0]))


def restore_latest_rules(base: str, token: str) -> None:
    try:
        latest = get(base + "/releases/latest", token)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return
        raise
    assets = {asset["name"]: asset for asset in latest.get("assets", [])}
    legacy = assets.get("blocked-domains.json.gz")
    evidence = assets.get("routing-evidence.zip")
    asset = legacy or evidence
    if asset is None:
        return
    payload = get(base + f"/releases/assets/{int(asset['id'])}", token,
                  as_json=False, limit=128 * 1024 * 1024, octet_stream=True)
    if legacy:
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as compressed:
            rules = compressed.read(512 * 1024 * 1024 + 1)
    else:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            info = archive.getinfo("blocked-domains.json")
            if info.file_size > 512 * 1024 * 1024:
                raise BuildError("Previous domain rules exceed size limit")
            rules = archive.read(info)
    if len(rules) > 512 * 1024 * 1024:
        raise BuildError("Previous domain rules exceed size limit")
    output = Path("previous/blocked-domains.json")
    output.parent.mkdir(exist_ok=True)
    output.write_bytes(rules)
    logger.info("Restored previous domain rules from release %s", latest["tag_name"])


def main() -> None:
    configure_logging()
    if os.environ.get("RESET_BASELINE", "false").lower() == "true":
        if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
            raise BuildError("Baseline reset is allowed only on explicit manual runs")
        logger.info("Explicit manual baseline reset: candidate will be labelled first-build.")
        return
    repository = os.environ["GITHUB_REPOSITORY"]
    branch = os.environ["BASELINE_BRANCH"]
    token = os.environ["GITHUB_TOKEN"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise BuildError("Invalid repository name")
    query = urllib.parse.urlencode({"branch": branch, "status": "success", "per_page": 10})
    base = f"https://api.github.com/repos/{repository}"
    runs = get(base + "/actions/workflows/build.yml/runs?" + query, token)["workflow_runs"]
    runs = [r for r in runs if str(r["id"]) != os.environ.get("GITHUB_RUN_ID") and r["event"] in {"schedule", "push", "workflow_dispatch"}]
    if not runs:
        restore_latest_rules(base, token)
        logger.info("No previous successful build on this branch. Bootstrap preview.")
        return
    for run in runs:
        artifacts = get(base + f"/actions/runs/{run['id']}/artifacts?per_page=100", token)["artifacts"]
        for artifact in artifacts:
            if artifact["name"] != "rules-manifest" or artifact["expired"]:
                continue
            data = read_manifest_zip(get(base + f"/actions/artifacts/{artifact['id']}/zip", token,
                                         as_json=False, limit=64 * 1024 * 1024))
            output = Path("previous/manifest.json")
            output.parent.mkdir(exist_ok=True)
            write_json(output, data)
            restore_latest_rules(base, token)
            logger.info(f"Restored baseline from successful run {run['id']}")
            return
    raise BuildError("Previous builds exist but no usable manifest remains; review and explicitly reset the baseline")


if __name__ == "__main__":
    try:
        main()
    except (BuildError, OSError, ValueError, KeyError, urllib.error.URLError) as exc:
        logger.error("BASELINE FAILED: %s", exc)
        raise SystemExit(1)
