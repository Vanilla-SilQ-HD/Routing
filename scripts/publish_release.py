"""Publish validated data through a draft, without ever replacing live assets.

Only GitHub Releases APIs are used. No router access or third-party actions.
"""
import argparse
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
import zipfile


class PublishError(Exception):
    pass


DATASETS = ("blocked-domains", "blocked-services-ip", "blocked-registry-ip", "routing-direct-exceptions")
BUILD_FILES = {name + suffix for name in DATASETS for suffix in (".srs", ".json", ".txt")}
BUILD_FILES |= {"manifest.json", "excluded.json", "probes.json", "domain-changes.json",
                "manual-rules.json", "report.html", "status.json", "updated.json"}
RELEASE_FILES = {name + suffix for name in DATASETS for suffix in (".srs", ".srs.sha256")}
RELEASE_FILES |= {"manifest.json", "domain-changes.json", "release.json", "SHA256SUMS",
                  "routing-evidence.zip"}
EVIDENCE_FILES = [name + ".json" for name in DATASETS]
EVIDENCE_FILES += ["excluded.json", "probes.json", "domain-changes.json", "manual-rules.json",
                   "report.html", "status.json", "updated.json"]
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


def verify_compiler(compiler, lock):
    if (not isinstance(compiler, dict)
            or compiler.get("version") != "sing-box version " + lock["sing_box_version"]
            or compiler.get("source_format_version") != lock["source_format_version"]
            or compiler.get("roundtrip") != "passed" or compiler.get("sing_box_check") != "passed"
            or compiler.get("network_service_started") is not False):
        raise PublishError("Compiler validation is missing or failed")


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
    verify_compiler(manifest["compiler"], lock)
    scope = manifest["scope"]
    expected_scope = {"domains_only": False, "personal_rules_included": False, "router_access": False,
                      "broad_ai_category_included": False, "ru_direct_category_included": False,
                      "ip_rules_included": True, "registry_ip_rules_included": True,
                      "direct_exceptions_included": True, "dns_configuration_included": False}
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
    service = manifest.get("service_networks")
    if not isinstance(service, dict) or not isinstance(service.get("sources"), list) or not service["sources"]:
        raise PublishError("Service network sources are missing")
    service_output = service.get("output", {})
    positive_counts = ("total_prefixes", "ipv4_prefixes", "ipv6_prefixes", "ipv4_addresses", "ipv6_addresses", "srs_bytes")
    if (not isinstance(service_output, dict)
            or any(type(service_output.get(key)) is not int or service_output[key] < 1 for key in positive_counts)
            or service_output["total_prefixes"] != service_output["ipv4_prefixes"] + service_output["ipv6_prefixes"]
            or service_output["srs_bytes"] != (directory / "blocked-services-ip.srs").stat().st_size):
        raise PublishError("Unexpected service network counts or binary size")
    verify_compiler(service.get("compiler"), lock)
    service_validation = service.get("validation", {})
    if (not isinstance(service_validation, dict)
            or service_validation.get("baseline") not in {"first-service-build", "previous-service-build", "previous-service-data-stale"}
            or service_validation.get("warnings") != []):
        raise PublishError("Service networks have an unknown baseline or unresolved validation warnings")
    if service_validation["baseline"] == "previous-service-data-stale":
        policy = json.loads((root / "config/policy.json").read_text(encoding="utf-8"))
        if (not service_validation.get("fetch_errors") or not service_validation.get("restored_from_built_at")
                or not 0 <= service_validation.get("stale_hours", -1) <= policy["validation"]["max_service_stale_hours"]):
            raise PublishError("Stale service fallback is missing its evidence or exceeds the time limit")
    registry = manifest.get("registry_ip")
    if not isinstance(registry, dict):
        raise PublishError("Registry IP evidence is missing")
    registry_output = registry.get("output", {})
    if (any(type(registry_output.get(key)) is not int for key in ("total_prefixes", "ipv4_prefixes", "ipv6_prefixes", "srs_bytes"))
            or registry_output["total_prefixes"] < 1
            or registry_output["total_prefixes"] != registry_output["ipv4_prefixes"] + registry_output["ipv6_prefixes"]
            or len(registry_output.get("prefixes", [])) != registry_output["total_prefixes"]
            or registry_output["srs_bytes"] != (directory / "blocked-registry-ip.srs").stat().st_size):
        raise PublishError("Unexpected registry IP counts or binary size")
    verify_compiler(registry.get("compiler"), lock)
    if (registry.get("validation", {}).get("baseline") not in {"first-registry-build", "previous-registry-build"}
            or registry["validation"].get("warnings") != []):
        raise PublishError("Registry IP has an unknown baseline or unresolved validation warnings")
    direct = manifest.get("direct_exceptions")
    if (not isinstance(direct, dict) or type(direct.get("output", {}).get("total_conditions")) is not int
            or direct["output"]["total_conditions"] < 0
            or direct["output"].get("srs_bytes") != (directory / "routing-direct-exceptions.srs").stat().st_size):
        raise PublishError("Unexpected Direct exception output")
    verify_compiler(direct.get("compiler"), lock)
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
    identity = {"schema_version": 1,
                "srs_sha256": {name + ".srs": manifest["output"]["files"][name + ".srs"] for name in DATASETS},
                "configuration_sha256": manifest["configuration_sha256"]}
    return hashlib.sha256(json_bytes(identity)).hexdigest()


def prepare_assets(candidate, destination, manifest, repository, run_id, attempt):
    destination.mkdir(parents=True, exist_ok=False)
    for name in ("manifest.json", "domain-changes.json"):
        shutil.copyfile(candidate / name, destination / name)
    for name in DATASETS:
        shutil.copyfile(candidate / (name + ".srs"), destination / (name + ".srs"))
        digest = manifest["output"]["files"][name + ".srs"]
        (destination / (name + ".srs.sha256")).write_bytes(f"{digest}  {name}.srs\n".encode("ascii"))
    with zipfile.ZipFile(destination / "routing-evidence.zip", "w",
                         compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in EVIDENCE_FILES:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, (candidate / name).read_bytes())
    digest = manifest["output"]["files"]["blocked-domains.srs"]
    metadata = {"schema_version": 1, "fingerprint": fingerprint(manifest), "srs_sha256": digest,
                "service_srs_sha256": manifest["output"]["files"]["blocked-services-ip.srs"],
                "dataset_srs_sha256": {name: manifest["output"]["files"][name + ".srs"] for name in DATASETS},
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


def human_size(value):
    if value < 1024:
        return f"{value} Б"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} КБ"
    return f"{value / 1024 / 1024:.2f} МБ"


def make_release_body(manifest, metadata, repository):
    owner, project = repository.split("/", 1)
    output = manifest["output"]
    service = manifest["service_networks"]["output"]
    registry = manifest["registry_ip"]["output"]
    direct = manifest["direct_exceptions"]["output"]
    changes = manifest["domain_diff"]
    labels = {
        "blocked-domains": ("Домены", "Маршрутизация и DNS", output["srs_bytes"]),
        "blocked-services-ip": ("Сети приложений", "Проверенные сети Telegram", service["srs_bytes"]),
        "blocked-registry-ip": ("Точные IP", "Подключения напрямую к IP", registry["srs_bytes"]),
        "routing-direct-exceptions": ("Direct-исключения", "Приоритетные правила Direct", direct["srs_bytes"]),
    }
    rows = []
    base = f"https://github.com/{repository}/releases/latest/download/"
    for name, (title, purpose, size) in labels.items():
        digest = metadata["dataset_srs_sha256"][name]
        rows.append(f"| [{title}]({base}{name}.srs) | {purpose} | {human_size(size)} | `{digest[:12]}…` |")
    pages = f"https://{owner.lower()}.github.io/{project}/"
    return f"""Выборочная маршрутизация: недоступные ресурсы через VPN, остальное напрямую.

## Результат сборки

| Показатель | Значение |
| --- | ---: |
| Доменных условий | **{output['total_conditions']:,}** |
| Точные имена / suffix | {output['exact']:,} / {output['suffix']:,} |
| Сети Telegram | **{service['total_prefixes']}** |
| Registry IP | **{registry['total_prefixes']}** |
| Direct-исключения | **{direct['total_conditions']}** |
| Источники | **{len(manifest['sources'])}** |
| sing-box | `{manifest['compiler']['version']}` |

## Скачать

| Набор | Назначение | Размер | SHA-256 |
| --- | --- | ---: | --- |
{chr(10).join(rows)}

Постоянные URL ведут на этот и последующие релизы. Для DNS используйте только доменный набор.

## Изменения покрытия

| Добавлено | Удалено | Новое покрытие | Потерянное покрытие |
| ---: | ---: | ---: | ---: |
| {changes['added']:,} | {changes['removed']:,} | **{changes['effective_added']:,}** | **{changes['effective_removed']:,}** |

Полный semantic diff: [domain-changes.json]({base}domain-changes.json). Источники и происхождение записей: [manifest.json]({base}manifest.json).

## Проверки

- unit-тесты и обязательные ожидания VPN/Direct;
- compile/decompile всех SRS и `sing-box check`;
- semantic diff без скрытой потери покрытия;
- SHA-256 и повторное скачивание каждого вложения;
- только точные `/32` и `/128` в registry-IP.

## Подключение и отчёты

- [Инструкция для AWG Manager](https://github.com/{repository}#подключение-к-awg-manager)
- [Интерактивный Routing Dashboard]({pages})
- [Evidence ZIP: исходники, probes и отчёт]({base}routing-evidence.zip)
- [SHA256SUMS]({base}SHA256SUMS)
- [Проверенный workflow]({metadata['run_url']})
"""


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
                for name in DATASETS:
                    expected_hash = metadata["dataset_srs_sha256"][name]
                    if previous.get("dataset_srs_sha256", {}).get(name) != expected_hash:
                        raise PublishError("Unchanged release has inconsistent binary metadata")
                    binary = github.download(inventory[name + ".srs"])
                    checksum = github.download(inventory[name + ".srs.sha256"], limit=1024)
                    if (hashlib.sha256(binary).hexdigest() != expected_hash
                            or checksum != (assets / (name + ".srs.sha256")).read_bytes()):
                        raise PublishError(f"Unchanged release failed binary integrity verification: {name}")
                return {"status": "unchanged", "release_url": latest["html_url"], "tag": latest["tag_name"]}
    body = make_release_body(manifest, metadata, github.repository)
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
            stream.write(f"Service IP SRS SHA-256: `{metadata['service_srs_sha256']}`\n")


if __name__ == "__main__":
    try:
        main()
    except (PublishError, OSError, ValueError, KeyError, urllib.error.URLError) as exc:
        print(f"PUBLICATION FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
