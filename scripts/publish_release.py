"""Publish validated data through a draft, without ever replacing live assets.

Only GitHub Releases APIs are used. No router access or third-party actions.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request


class PublishError(Exception):
    pass


BUILD_FILES = {
    "blocked-domains.srs", "blocked-domains.json", "blocked-domains.txt",
    "manifest.json", "excluded.json", "probes.json", "report.html",
}
RELEASE_FILES = {
    "blocked-domains.srs", "blocked-domains.srs.sha256", "blocked-domains.json.gz",
    "manifest.json", "excluded.json", "probes.json", "report.html", "release.json",
    "SHA256SUMS",
}
MAX_ASSET_BYTES = 128 * 1024 * 1024


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def parse_checksums(text, expected):
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
        if not match or match[2] not in expected or match[2] in result:
            raise PublishError("Invalid, duplicate or unexpected checksum entry")
        result[match[2]] = match[1]
    if set(result) != expected:
        raise PublishError("Incomplete checksum inventory")
    return result


def initial_baseline_allowed(latest_release, reset_baseline, event):
    if reset_baseline and event != "workflow_dispatch":
        raise PublishError("Baseline reset requires an explicit manual workflow run")
    return latest_release is None or reset_baseline


def verify_candidate(directory, root, commit, *, allow_initial_baseline=False):
    if {p.name for p in directory.iterdir()} != BUILD_FILES | {"SHA256SUMS"}:
        raise PublishError("Unexpected build artifact inventory")
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file():
            raise PublishError("Only regular files may be published")
    checksums = parse_checksums((directory / "SHA256SUMS").read_text(encoding="utf-8"), BUILD_FILES)
    for name, expected in checksums.items():
        if sha256(directory / name) != expected:
            raise PublishError(f"Build checksum mismatch: {name}")
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest["schema_version"] != 1 or manifest["offline_replay"] is not False:
        raise PublishError("Release must be a fresh online build with a supported manifest")
    if manifest["environment"]["github_commit"] != commit:
        raise PublishError("Artifact was built from a different commit")
    recipe_paths = list((root / "config").glob("*.json")) + list((root / "scripts").glob("*.py"))
    recipe_paths += [root / "requirements.txt", root / ".github/workflows/build.yml"]
    recipe = {p.relative_to(root).as_posix(): sha256(p) for p in recipe_paths}
    if manifest["configuration_sha256"] != recipe:
        raise PublishError("Artifact recipe does not match this checkout")
    lock = json.loads((root / "config/tools-lock.json").read_text(encoding="utf-8"))
    compiler = manifest["compiler"]
    if (compiler["version"] != "sing-box version " + lock["sing_box_version"]
            or compiler["source_format_version"] != lock["source_format_version"]
            or compiler["roundtrip"] != "passed" or compiler["sing_box_check"] != "passed"
            or compiler["network_service_started"] is not False):
        raise PublishError("Compiler validation is missing or failed")
    scope = manifest["scope"]
    expected_scope = {"domains_only": True, "personal_rules_included": False, "router_access": False,
                      "broad_ai_category_included": False, "ru_direct_category_included": False,
                      "ip_rules_included": False, "dns_configuration_included": False}
    if scope != expected_scope:
        raise PublishError("Unexpected routing scope")
    output = manifest["output"]
    expected_output = BUILD_FILES - {"manifest.json", "report.html"}
    if set(output["files"]) != expected_output:
        raise PublishError("Unexpected manifest output inventory")
    if any(output["files"][name] != checksums[name] for name in expected_output):
        raise PublishError("Manifest hashes do not match the candidate")
    if output["srs_bytes"] != (directory / "blocked-domains.srs").stat().st_size or output["total_conditions"] < 1:
        raise PublishError("Unexpected binary size or empty rule-set")
    validation = manifest["validation"]
    if validation["baseline"] == "first-build":
        expected = ["First build has no previous published version to compare."]
        if not allow_initial_baseline or validation["warnings"] != expected:
            raise PublishError("Initial baseline requires a first release or an explicit manual reset")
    elif validation["baseline"] != "previous-successful-or-approved-manifest" or validation["warnings"]:
        raise PublishError("Build has an unknown baseline or unresolved validation warnings")
    return manifest


def fingerprint(manifest):
    # Fetch timestamps and provenance-only changes do not justify a new binary release.
    identity = {"schema_version": 1, "srs_sha256": manifest["output"]["files"]["blocked-domains.srs"],
                "configuration_sha256": manifest["configuration_sha256"]}
    return hashlib.sha256(json_bytes(identity)).hexdigest()


def prepare_assets(candidate, destination, manifest, repository, run_id, attempt):
    destination.mkdir(parents=True, exist_ok=False)
    for name in ("blocked-domains.srs", "manifest.json", "excluded.json", "probes.json", "report.html"):
        shutil.copyfile(candidate / name, destination / name)
    with (candidate / "blocked-domains.json").open("rb") as source:
        with (destination / "blocked-domains.json.gz").open("wb") as target:
            with gzip.GzipFile(filename="", mode="wb", fileobj=target, mtime=0) as compressed:
                shutil.copyfileobj(source, compressed)
    digest = manifest["output"]["files"]["blocked-domains.srs"]
    (destination / "blocked-domains.srs.sha256").write_bytes(f"{digest}  blocked-domains.srs\n".encode("ascii"))
    metadata = {"schema_version": 1, "fingerprint": fingerprint(manifest), "srs_sha256": digest,
                "github_commit": manifest["environment"]["github_commit"], "built_at": manifest["built_at"],
                "run_url": f"https://github.com/{repository}/actions/runs/{run_id}/attempts/{attempt}"}
    (destination / "release.json").write_bytes(json_bytes(metadata))
    lines = [f"{sha256(path)}  {path.name}\n" for path in sorted(destination.iterdir())]
    (destination / "SHA256SUMS").write_bytes("".join(lines).encode("ascii"))
    return metadata


class CredentialSafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise PublishError("Refusing an insecure asset redirect")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header("Authorization")
        return redirected


class GitHub:
    def __init__(self, repository, token):
        self.repository, self.token = repository, token
        self.base = f"https://api.github.com/repos/{repository}"
        self.opener = urllib.request.build_opener(CredentialSafeRedirect())

    def request(self, method, url, data=None, binary=False, limit=MAX_ASSET_BYTES, upload=False):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc not in {"api.github.com", "uploads.github.com"}:
            raise PublishError("Refusing to send credentials outside GitHub API hosts")
        headers = {"Authorization": "Bearer " + self.token, "User-Agent": "Routing-release/1",
                   "X-GitHub-Api-Version": "2022-11-28", "Cache-Control": "no-cache",
                   "Accept": "application/octet-stream" if binary else "application/vnd.github+json"}
        if data is not None:
            headers["Content-Type"] = "application/octet-stream" if upload else "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        with self.opener.open(request, timeout=120) as response:
            payload = response.read(limit + 1)
        if len(payload) > limit:
            raise PublishError("GitHub response exceeds size limit")
        return payload if binary else json.loads(payload)

    def latest(self):
        try:
            return self.request("GET", self.base + "/releases/latest")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    def create_draft(self, tag, commit, title, body):
        return self.request("POST", self.base + "/releases", json_bytes({
            "tag_name": tag, "target_commitish": commit, "name": title, "body": body,
            "draft": True, "prerelease": False, "make_latest": "false",
        }))

    def upload(self, release_id, path):
        if path.stat().st_size > MAX_ASSET_BYTES:
            raise PublishError("Release asset exceeds size limit")
        url = f"https://uploads.github.com/repos/{self.repository}/releases/{int(release_id)}/assets?"
        return self.request("POST", url + urllib.parse.urlencode({"name": path.name}), path.read_bytes(), upload=True)

    def download(self, asset, limit=MAX_ASSET_BYTES):
        return self.request("GET", self.base + f"/releases/assets/{int(asset['id'])}", binary=True, limit=limit)

    def publish(self, release_id):
        return self.request("PATCH", self.base + f"/releases/{int(release_id)}",
                            json_bytes({"draft": False, "prerelease": False, "make_latest": "true"}))


def publish(assets, manifest, metadata, github, tag):
    if {p.name for p in assets.iterdir()} != RELEASE_FILES:
        raise PublishError("Unexpected release inventory")
    latest = github.latest()
    if latest:
        inventory = {a["name"]: a for a in latest["assets"]}
        if "release.json" in inventory:
            previous = json.loads(github.download(inventory["release.json"], limit=1024 * 1024))
            if previous.get("fingerprint") == metadata["fingerprint"]:
                if set(inventory) != RELEASE_FILES or len(latest["assets"]) != len(RELEASE_FILES):
                    raise PublishError("Unchanged release has an incomplete asset inventory")
                binary = github.download(inventory["blocked-domains.srs"])
                checksum = github.download(inventory["blocked-domains.srs.sha256"], limit=1024)
                if (hashlib.sha256(binary).hexdigest() != metadata["srs_sha256"]
                        or checksum != (assets / "blocked-domains.srs.sha256").read_bytes()):
                    raise PublishError("Unchanged release failed binary integrity verification")
                return {"status": "unchanged", "release_url": latest["html_url"], "tag": latest["tag_name"]}
    stable = f"https://github.com/{github.repository}/releases/latest/download/blocked-domains.srs"
    body = (f"Автоматическая доменная база для выборочного VPN.\n\n"
            f"Условий: **{manifest['output']['total_conditions']:,}**. "
            f"sing-box: `{manifest['compiler']['version']}`.\n\n"
            f"[Постоянная ссылка на .srs]({stable}) · [Проверенная сборка]({metadata['run_url']})\n\n"
            f"SHA-256: `{metadata['srs_sha256']}`\n\n"
            "Исходник опубликован в `blocked-domains.json.gz`; происхождение и проверки — в `manifest.json`. "
            "Контрольные суммы всех вложений — в `SHA256SUMS`.\n\n"
            "Состав определяется публичными источниками и политикой репозитория. "
            "Набор содержит только доменные условия. Маршруты и DNS задаются в конфигурации sing-box.")
    release = github.create_draft(tag, manifest["environment"]["github_commit"],
                                  "Routing · " + manifest["built_at"], body)
    if release.get("draft") is not True:
        raise PublishError("GitHub did not create a draft; refusing asset upload")
    for path in sorted(assets.iterdir()):
        asset = github.upload(release["id"], path)
        if asset["state"] != "uploaded" or asset["size"] != path.stat().st_size or asset["name"] != path.name:
            raise PublishError(f"Incomplete asset upload: {path.name}")
        digest = sha256(path)
        if asset.get("digest") and asset["digest"] != "sha256:" + digest:
            raise PublishError(f"GitHub asset digest mismatch: {path.name}")
        # Verify actual stored bytes, even when GitHub does not return a digest.
        if hashlib.sha256(github.download(asset)).hexdigest() != digest:
            raise PublishError(f"Downloaded draft asset differs: {path.name}")
    published = github.publish(release["id"])
    if published["draft"] or published["prerelease"]:
        raise PublishError("Release was not published as a stable version")
    return {"status": "published", "release_url": published["html_url"], "tag": published["tag_name"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="incoming/dist")
    parser.add_argument("--output", default="release")
    args = parser.parse_args()
    if os.environ.get("GITHUB_REF") != "refs/heads/main" or os.environ.get("GITHUB_EVENT_NAME") not in {"push", "schedule", "workflow_dispatch"}:
        raise PublishError("Publication is restricted to trusted main-branch workflows")
    repository = os.environ["GITHUB_REPOSITORY"]
    commit, run_id, attempt = (os.environ[key] for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise PublishError("Invalid repository or commit")
    if not run_id.isdigit() or not attempt.isdigit():
        raise PublishError("Invalid workflow run identity")
    candidate, assets = Path(args.input), Path(args.output)
    github = GitHub(repository, os.environ["GITHUB_TOKEN"])
    allow_initial = initial_baseline_allowed(github.latest(),
        os.environ.get("RESET_BASELINE", "false").lower() == "true", os.environ["GITHUB_EVENT_NAME"])
    manifest = verify_candidate(candidate, Path.cwd(), commit, allow_initial_baseline=allow_initial)
    if manifest["validation"]["baseline"] == "first-build":
        print("Initial baseline accepted: first release or explicitly requested manual reset.", flush=True)
    metadata = prepare_assets(candidate, assets, manifest, repository, run_id, attempt)
    result = publish(assets, manifest, metadata, github, f"rules-{run_id}-{attempt}")
    print(json.dumps(result), flush=True)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write(f"Release **{result['status']}**: [{result['tag']}]({result['release_url']})\n\n")
            stream.write(f"SRS SHA-256: `{metadata['srs_sha256']}`\n")


if __name__ == "__main__":
    try:
        main()
    except (PublishError, OSError, ValueError, KeyError, urllib.error.URLError) as exc:
        print(f"PUBLICATION FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
