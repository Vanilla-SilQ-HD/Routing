"""Build a domain-only VPN selector dataset. No router/API access is implemented."""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import datetime as dt
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import idna

ROOT = Path(__file__).resolve().parents[1]
USER_AGENT = "selective-vpn-rules/1 (public domain lists only)"
ASCII_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class BuildError(Exception):
    pass


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise BuildError("Refusing an HTTP downgrade redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_source(source, cache, offline=False):
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / (source["id"] + ".data")
    metadata_path = cache / (source["id"] + ".metadata.json")
    if offline:
        if not target.exists() or not metadata_path.exists():
            raise BuildError(f"Missing offline source: {source['id']}")
        metadata = read_json(metadata_path)
        if metadata["url"] != source["url"] or file_sha256(target) != metadata["sha256"]:
            raise BuildError(f"Offline cache hash/URL mismatch: {source['id']}")
        return target, metadata
    if urllib.parse.urlsplit(source["url"]).scheme != "https":
        raise BuildError("All input URLs must use HTTPS")
    opener = urllib.request.build_opener(HTTPSRedirect())
    error = None
    for attempt in range(3):
        temporary = target.with_suffix(".partial")
        try:
            started = time.monotonic()
            request = urllib.request.Request(source["url"], headers={"User-Agent": USER_AGENT})
            with opener.open(request, timeout=30) as response, temporary.open("wb") as stream:
                digest, size = hashlib.sha256(), 0
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > source["max_bytes"]:
                        raise BuildError(f"Source exceeds size limit: {source['id']}")
                    if time.monotonic() - started > 150:
                        raise BuildError(f"Source download exceeded time limit: {source['id']}")
                    digest.update(chunk)
                    stream.write(chunk)
                if not size:
                    raise BuildError(f"Empty source: {source['id']}")
                metadata = {
                    "id": source["id"], "url": source["url"], "effective_url": response.url,
                    "fetched_at": utc_now(), "bytes": size, "sha256": digest.hexdigest(),
                    "last_modified": response.headers.get("Last-Modified"),
                    "etag": response.headers.get("ETag"),
                }
            os.replace(temporary, target)
            write_json(metadata_path, metadata)
            print(f"Fetched {source['id']}: {size:,} bytes", flush=True)
            return target, metadata
        except (OSError, urllib.error.URLError, BuildError) as exc:
            error = exc
            temporary.unlink(missing_ok=True)
            if attempt < 2:
                time.sleep(attempt + 1)
    raise BuildError(f"Cannot fetch required source {source['id']}: {error}")


def normalize_domain(value):
    """Canonical IDNA name; never turn a URL, IP or wildcard into a domain."""
    if not isinstance(value, str):
        raise ValueError("domain is not a string")
    value = value.strip().lower()
    if value.endswith("."):
        value = value[:-1]
    if not value or any(c in value for c in "/:@*\\?#"):
        raise ValueError("not a plain domain name")
    if re.fullmatch(r"[0-9.]+", value):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            raise ValueError("IP addresses are not domain rules")
    if not value.isascii() or any(label.startswith("xn--") for label in value.split(".")):
        try:
            value = idna.encode(value, uts46=True, transitional=False, std3_rules=True).decode("ascii")
        except idna.IDNAError as exc:
            raise ValueError("invalid IDNA name") from exc
    if len(value) > 253 or any(not ASCII_LABEL.fullmatch(label) for label in value.split(".")):
        raise ValueError("invalid DNS labels")
    return value


def parse_source(path, source, max_invalid_fraction):
    exact, suffix = set(), set()
    invalid, samples, records = 0, [], 0

    def accept(value, kind):
        nonlocal invalid, records
        records += 1
        try:
            name = normalize_domain(value)
        except ValueError as exc:
            invalid += 1
            if len(samples) < 30:
                samples.append({"value": str(value)[:200], "reason": str(exc)})
        else:
            (exact if kind == "domain" else suffix).add(name)

    if source["format"] == "suffix-lines":
        with Path(path).open(encoding="utf-8-sig") as stream:
            for line in stream:
                value = line.strip()
                if not value or value.startswith(("#", "//")):
                    continue
                if value.startswith("*."):
                    value = value[2:]
                elif value.startswith("."):
                    value = value[1:]
                accept(value, "domain_suffix")
    elif source["format"] == "singbox-domains":
        data = read_json(path)
        if set(data) != {"version", "rules"} or data["version"] not in {1, 2, 3, 4} or not isinstance(data["rules"], list):
            raise BuildError(f"Unexpected rule-set schema: {source['id']}")
        for rule in data["rules"]:
            if not isinstance(rule, dict) or not rule or set(rule) - {"domain", "domain_suffix"}:
                raise BuildError(f"Non-domain or logical condition in {source['id']}; refusing to flatten it")
            if not any(rule.values()):
                raise BuildError(f"Empty match-all rule in {source['id']}")
            for kind, values in rule.items():
                if not isinstance(values, list):
                    raise BuildError(f"Unexpected domain list in {source['id']}")
                for value in values:
                    accept(value, kind)
    else:
        raise BuildError(f"Unsupported source format: {source['format']}")
    count = len(exact) + len(suffix)
    if count < source["min_entries"]:
        raise BuildError(f"Source {source['id']} has only {count} unique conditions; minimum {source['min_entries']}")
    if records and invalid / records > max_invalid_fraction:
        raise BuildError(f"Too many invalid records in {source['id']}: {invalid}/{records}; examples: {samples[:3]}")
    return exact, suffix, {
        "unique_conditions": count, "exact": len(exact), "suffix": len(suffix),
        "records": records, "invalid": invalid, "invalid_samples": samples,
        "duplicate_records": records - invalid - count,
    }


class PublicSuffixes:
    def __init__(self, text):
        self.exact, self.wildcard, self.exceptions = set(), set(), set()
        self.private_wildcard = set()
        private = False
        for line in text.splitlines():
            line = line.strip()
            if line == "// ===BEGIN PRIVATE DOMAINS===":
                private = True
            if not line or line.startswith("//"):
                continue
            target = self.exact
            if line.startswith("!:"):
                raise BuildError("Malformed PSL exception")
            if line.startswith("!"):
                target, line = self.exceptions, line[1:]
            elif line.startswith("*."):
                target, line = self.wildcard, line[2:]
            normalized = normalize_domain(line)
            target.add(normalized)
            if private and target is self.wildcard:
                self.private_wildcard.add(normalized)

    @property
    def count(self):
        return len(self.exact) + len(self.wildcard) + len(self.exceptions)

    def is_public_suffix(self, name):
        if name in self.exceptions:
            return False
        if "." not in name or name in self.exact:
            return True
        return name.partition(".")[2] in self.wildcard

    def is_broad_routing_suffix(self, name):
        # PRIVATE wildcard entries often isolate individual tenants' cookies.
        # e.g. *.eth.limo does NOT mean blocked-tenant.eth.limo covers all eth.limo.
        if name in self.private_wildcard:
            return True
        if name.partition(".")[2] in self.private_wildcard and name not in self.exact:
            return False
        return self.is_public_suffix(name)


def parents(name):
    offset = name.find(".")
    while offset >= 0:
        yield name[offset + 1:]
        offset = name.find(".", offset + 1)


def exclusion_reason(kind, name, shared, psl, service_owned=()):
    if name in shared:
        return "shared-infrastructure: " + shared[name]
    if kind == "domain_suffix" and psl.is_broad_routing_suffix(name):
        if name in service_owned or any(parent in service_owned for parent in parents(name)):
            return None
        if "." not in name and name not in psl.exact:
            return "single-label: имя без доменной зоны"
        return "public-suffix: целая зона или общая платформа (PSL ICANN/PRIVATE)"
    return None


def match_rule(name, exact, suffix):
    if name in exact:
        return "domain", name
    if name in suffix:
        return "domain_suffix", name
    for parent in parents(name):
        if parent in suffix:
            return "domain_suffix", parent
    return None


def minimize(exact, suffix):
    """Remove only rules covered by an existing suffix, without creating any new suffix."""
    minimal_suffix = {name: mask for name, mask in suffix.items() if not any(parent in suffix for parent in parents(name))}
    minimal_exact = {name: mask for name, mask in exact.items() if not match_rule(name, {}, suffix)}
    return minimal_exact, minimal_suffix


def validate_previous(previous, stats, count, policy, now=None):
    if previous is None:
        return {"baseline": "first-build", "warnings": ["First build has no previous published version to compare."]}
    if previous.get("schema_version") != 1:
        raise BuildError("Unsupported previous manifest version")
    v = policy["validation"]
    current_time = now or dt.datetime.now(dt.timezone.utc)
    age = (current_time - dt.datetime.fromisoformat(previous["built_at"])).total_seconds() / 86400
    if age < -0.1 or age > v["max_previous_age_days"]:
        raise BuildError("Previous baseline is stale or from the future; review before resuming publication")
    previous_sources = {s["id"]: s for s in previous["sources"]}
    if set(previous_sources) != {s["id"] for s in stats}:
        raise BuildError("Source composition changed; explicit baseline review required")
    for current in stats:
        before = previous_sources[current["id"]]["unique_conditions"]
        if not before or not before * (1 - v["max_source_drop_fraction"]) <= current["unique_conditions"] <= before * (1 + v["max_source_growth_fraction"]):
            raise BuildError(f"Unexpected source size change: {current['id']} {before} -> {current['unique_conditions']}")
    before = previous["output"]["total_conditions"]
    if not before or not before * (1 - v["max_output_drop_fraction"]) <= count <= before * (1 + v["max_output_growth_fraction"]):
        raise BuildError(f"Unexpected output size change: {before} -> {count}")
    return {"baseline": "previous-successful-or-approved-manifest", "baseline_built_at": previous["built_at"], "warnings": []}


def compile_and_verify(directory, executable, source_format_version):
    version = subprocess.run([str(executable), "version"], capture_output=True, text=True, check=True, timeout=15).stdout.splitlines()[0]
    source, binary, decoded = (directory / name for name in ("blocked-domains.json", "blocked-domains.srs", "roundtrip.json"))
    subprocess.run([str(executable), "rule-set", "compile", "--output", str(binary), str(source)], check=True, capture_output=True, text=True, timeout=180)
    subprocess.run([str(executable), "rule-set", "decompile", "--output", str(decoded), str(binary)], check=True, capture_output=True, text=True, timeout=180)
    original, result = read_json(source), read_json(decoded)
    def conditions(data):
        groups = {"domain": set(), "domain_suffix": set()}
        for rule in data["rules"]:
            if set(rule) - groups.keys():
                raise BuildError("Compiler roundtrip introduced a non-domain condition")
            for kind, values in rule.items():
                groups[kind].update(values)
        return groups
    if conditions(original) != conditions(result):
        raise BuildError("SRS compile/decompile changed the domain conditions")
    decoded.unlink()
    config = directory / "validation-config.json"
    write_json(config, {
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rule_set": [{"type": "local", "tag": "generated", "format": "binary", "path": str(binary.resolve())}],
                  "rules": [{"rule_set": ["generated"], "outbound": "direct"}], "final": "direct"},
    })
    subprocess.run([str(executable), "check", "--config", str(config)], check=True, capture_output=True, text=True, timeout=180)
    config.unlink()
    return {"version": version, "executable_sha256": file_sha256(executable), "source_format_version": source_format_version,
            "roundtrip": "passed", "sing_box_check": "passed", "network_service_started": False}


def make_report(manifest, exclusions, probes):
    e = html.escape
    def table(headings, rows):
        return "<table><thead><tr>" + "".join(f"<th>{e(str(x))}</th>" for x in headings) + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{e(str(x))}</td>" for x in row) + "</tr>" for row in rows) + "</tbody></table>"
    source_table = table(["Источник", "Уникальных условий", "Неверных записей", "SHA-256"],
                         [[s["id"], f"{s['unique_conditions']:,}", s["invalid"], s["sha256"]] for s in manifest["sources"]])
    probe_table = table(["Домен", "Совпадение с базой", "Условие", "Источники"],
                        [[p["domain"], p["base_decision"], p.get("matched_rule") or "—", ", ".join(p["sources"])] for p in probes])
    excluded_table = table(["Условие", "Причина", "Источники"],
                           [[x["domain"], x["reason"], ", ".join(x["sources"])] for x in exclusions])
    out = manifest["output"]
    return f'''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Проверка автоматической VPN-базы</title><style>body{{font:16px/1.55 system-ui,sans-serif;background:#f6f8fb;color:#152137;max-width:1200px;margin:32px auto;padding:0 24px}}h1,h2{{line-height:1.2}}table{{border-collapse:collapse;width:100%;background:white;margin:20px 0}}td,th{{padding:10px 12px;border:1px solid #dce3ed;text-align:left;overflow-wrap:anywhere}}th{{background:#e9eff8}}.box{{background:#e6f1ff;border-left:4px solid #3971ce;padding:16px}}code{{background:#e9eff8;padding:2px 4px}}small{{color:#506078}}</style>
<h1>Автоматическая база для выборочного VPN</h1><p>Сборка: {e(manifest['built_at'])}. Все времена UTC.</p>
<p class="box"><b>Только подготовка данных.</b> Роутер не подключался, конфигурация не менялась. Личные IP, рабочие VPN и их ключи отсутствуют в проекте. Решения ниже относятся только к базе; личные исключения роутера имеют отдельный приоритет.</p>
<h2>Результат</h2><p>{out['total_conditions']:,} доменных условий: {out['suffix']:,} суффиксов и {out['exact']:,} точных имён. SRS: {out['srs_bytes']:,} байт. Удалено широких условий: {len(exclusions)}. Избыточных условий после объединения: {manifest['counts']['redundant_conditions_removed']:,}.</p>
<p>Сборка из исходников до минимизации. Широкие записи удаляются отдельно; явно перечисленные поддомены сохраняются. Категорий «Россия» и «все ИИ», IP-подсетей, ASN и персональных исключений в базе нет.</p>
<h2>Источники</h2>{source_table}<p>Дата получения не доказывает актуальность каждой блокировки. В частности, unavailable-in-russia использует накопительное добавление. Полные URL, времена и хеши записаны в manifest.json.</p>
<h2>Проверка доменов</h2><p>VPN — есть совпадение с базой; Direct — совпадения нет. Это не сетевой тест доступности и не чтение действующих правил роутера. Имена из этого раздела не используются как принудительные исключения.</p>{probe_table}
<h2>Удалённые широкие условия</h2><p>Удаление родительского условия не удаляет его отдельно перечисленные поддомены. PSL включает ICANN и PRIVATE. Зависимости отдельных ограниченных сервисов (например, claudeusercontent.com) сохраняются при наличии в источниках; политика не добавляет их самостоятельно. PRIVATE wildcard не используется для удаления отдельных доменов арендаторов.</p>{excluded_table}
<h2>Валидация</h2><p>Компиляция SRS, обратное декодирование с сравнением условий и sing-box check: выполнены. Программа sing-box запускалась только как компилятор и валидатор, без сетевого сервиса.</p>
<p>Резкое изменение размера относительно предыдущей успешной или принятой версии останавливает сборку. Ошибка обязательного источника не заменяется неполным или пустым набором. Текущий тип сравнения: {e(manifest['validation']['baseline'])}. GitHub Actions публикует проверенный результат в Releases отдельным этапом. Этот отчёт сам по себе не подтверждает публикацию. Подключение к роутеру отсутствует.</p>
<h2>Границы результата</h2><p>Домены из источников не равны гарантированной текущей блокировке у любого провайдера. Фильтрация общей платформы может оставить непокрытыми блокировки, для которых источник не перечисляет конкретные поддомены. Доменные правила сами по себе не покрывают голосовой UDP/IP-трафик или скрытое имя сайта. Ресурсы роутера, DNS, IPv6 и реальные маршруты проверяются на следующем согласованном этапе.</p>
</html>'''


def build(args):
    started = time.monotonic()
    root = Path(args.root).resolve()
    sources_config = read_json(root / "config/sources.json")
    policy = read_json(root / "config/policy.json")
    sources = sources_config["sources"]
    psl_source = sources_config["public_suffix_list"]
    all_sources = sources + [psl_source]
    cache = root / "cache/sources"
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = {s["id"]: pool.submit(fetch_source, s, cache, args.offline) for s in all_sources}
        fetched = {key: future.result() for key, future in futures.items()}
    if args.fetch_only:
        print("All required public inputs cached and hashed. No compilation performed.")
        return
    psl = PublicSuffixes(fetched[psl_source["id"]][0].read_text(encoding="utf-8-sig"))
    if psl.count < psl_source["min_entries"]:
        raise BuildError("Public Suffix List is unexpectedly small")
    exact, suffix, exclusions = {}, {}, {}
    stats, total_conditions, skipped = [], 0, 0
    shared = {normalize_domain(name): reason for name, reason in policy["shared_roots"].items()}
    service_owned = {normalize_domain(name) for name in policy.get("service_owned_suffixes", {})}
    if shared.keys() & service_owned:
        raise BuildError("A domain cannot be both shared infrastructure and a service-owned exception")
    for i, source in enumerate(sources):
        source_exact, source_suffix, parsed = parse_source(fetched[source["id"]][0], source, policy["validation"]["max_invalid_fraction"])
        metadata = dict(fetched[source["id"]][1], **parsed, description=source["description"])
        if "caveat" in source:
            metadata["caveat"] = source["caveat"]
        total_conditions += parsed["unique_conditions"]
        rejected_here = 0
        for kind, names, merged in (("domain", source_exact, exact), ("domain_suffix", source_suffix, suffix)):
            for name in names:
                reason = exclusion_reason(kind, name, shared, psl, service_owned)
                if reason:
                    key = (kind, name)
                    record = exclusions.setdefault(key, {"kind": kind, "domain": name, "reason": reason, "sources": []})
                    record["sources"].append(source["id"])
                    rejected_here += 1
                    continue
                merged[name] = merged.get(name, 0) | (1 << i)
        metadata["filtered_conditions"] = rejected_here
        stats.append(metadata)
        skipped += rejected_here
        print(f"Parsed {source['id']}: {parsed['unique_conditions']:,} conditions, {rejected_here} broad rules excluded", flush=True)
    before_minimize = len(exact) + len(suffix)
    original_exact, original_suffix = exact, suffix
    exact, suffix = minimize(original_exact, original_suffix)
    count = len(exact) + len(suffix)
    if count < policy["validation"]["minimum_output_domains"]:
        raise BuildError(f"Unexpectedly small final set: {count}")
    for name in suffix:
        if exclusion_reason("domain_suffix", name, shared, psl, service_owned):
            raise BuildError("Broad rule survived filtering")
    for names in (original_exact, original_suffix):
        if any(not match_rule(name, exact, suffix) for name in names):
            raise BuildError("Minimization lost an input condition")
    previous = read_json(args.previous) if args.previous else None
    validation = validate_previous(previous, stats, count, policy)
    probes = []
    for domain in read_json(root / "config/probes.json")["domains"]:
        name = normalize_domain(domain)
        match = match_rule(name, exact, suffix)
        mask = original_exact.get(name, 0) | original_suffix.get(name, 0)
        for parent in parents(name):
            mask |= original_suffix.get(parent, 0)
        probes.append({"domain": name, "base_decision": "VPN" if match else "Direct",
                       "matched_type": match[0] if match else None, "matched_rule": match[1] if match else None,
                       "sources": [s["id"] for i, s in enumerate(sources) if mask & (1 << i)]})
    lock = read_json(root / "config/tools-lock.json")
    compiler = Path(args.sing_box).resolve() if args.sing_box else root / ".tools" / ("sing-box.exe" if os.name == "nt" else "sing-box")
    if not compiler.is_file():
        raise BuildError("Compiler missing. Run scripts/install_tools.py first.")
    target = Path(args.output).resolve() if args.output else root / "dist"
    if target.exists() and any(target.iterdir()):
        raise BuildError(f"Output is not empty; refusing to overwrite a previous build: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".rules-candidate-", dir=target.parent) as temporary:
        stage = Path(temporary)
        rules = {}
        if exact:
            rules["domain"] = sorted(exact)
        if suffix:
            rules["domain_suffix"] = sorted(suffix)
        write_json(stage / "blocked-domains.json", {"version": lock["source_format_version"], "rules": [rules]})
        with (stage / "blocked-domains.txt").open("w", encoding="utf-8", newline="\n") as stream:
            for name in sorted(exact):
                stream.write("full:" + name + "\n")
            for name in sorted(suffix):
                stream.write("domain:" + name + "\n")
        compilation = compile_and_verify(stage, compiler, lock["source_format_version"])
        if compilation["version"] != "sing-box version " + lock["sing_box_version"]:
            raise BuildError("Unexpected compiler version; update the tool lock explicitly")
        excluded = [exclusions[key] for key in sorted(exclusions)]
        write_json(stage / "excluded.json", excluded)
        write_json(stage / "probes.json", probes)
        recipe_paths = list((root / "config").glob("*.json")) + list((root / "scripts").glob("*.py")) + [root / "requirements.txt", root / ".github/workflows/build.yml"]
        config_hashes = {str(path.relative_to(root)).replace(os.sep, "/"): file_sha256(path) for path in sorted(recipe_paths)}
        source_bits = collections.Counter(mask for mask in original_exact.values())
        source_bits.update(original_suffix.values())
        intersections = []
        for mask, amount in sorted(source_bits.items()):
            intersections.append({"sources": [s["id"] for i, s in enumerate(sources) if mask & (1 << i)], "unique_conditions": amount})
        manifest = {
            "schema_version": 1, "built_at": utc_now(), "offline_replay": args.offline,
            "sources": stats, "public_suffix_list": dict(fetched[psl_source["id"]][1], parsed_rules=psl.count),
            "configuration_sha256": config_hashes, "compiler": compilation,
            "environment": {"python": sys.version.split()[0], "idna": idna.__version__, "github_commit": os.environ.get("GITHUB_SHA")},
            "counts": {"source_unique_conditions_sum": total_conditions, "filtered_source_conditions_sum": skipped,
                       "unique_filtered_conditions": before_minimize,
                       "duplicate_conditions_across_sources": total_conditions - skipped - before_minimize,
                       "redundant_conditions_removed": before_minimize - count},
            "exact_intersections_before_minimization": intersections,
            "output": {"total_conditions": count, "exact": len(exact), "suffix": len(suffix),
                       "srs_bytes": (stage / "blocked-domains.srs").stat().st_size,
                       "files": {name: file_sha256(stage / name) for name in ("blocked-domains.json", "blocked-domains.srs", "blocked-domains.txt", "excluded.json", "probes.json")}},
            "validation": validation, "elapsed_seconds": round(time.monotonic() - started, 2),
            "scope": {"domains_only": True, "personal_rules_included": False, "router_access": False,
                      "broad_ai_category_included": False, "ru_direct_category_included": False,
                      "ip_rules_included": False, "dns_configuration_included": False},
        }
        write_json(stage / "manifest.json", manifest)
        (stage / "report.html").write_text(make_report(manifest, excluded, probes), encoding="utf-8")
        (stage / "SHA256SUMS").write_text("".join(f"{file_sha256(path)}  {path.name}\n" for path in sorted(stage.iterdir()) if path.is_file()), encoding="utf-8")
        if target.exists():
            target.rmdir()  # Only the empty directory checked above, never a recursive removal.
        stage.rename(target)
    print(json.dumps({"output": str(target), "domains": count, "srs_bytes": manifest["output"]["srs_bytes"],
                      "excluded_broad_conditions": len(excluded), "validation": compilation}, ensure_ascii=False), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--offline", action="store_true", help="Replay only SHA-256-verified cached inputs; no network")
    parser.add_argument("--fetch-only", action="store_true")
    parser.add_argument("--previous", help="Previous successful/approved manifest.json for drift guards")
    parser.add_argument("--output", help="A new, empty output directory")
    parser.add_argument("--sing-box", help="Path to the pinned sing-box compiler")
    args = parser.parse_args()
    try:
        build(args)
    except (BuildError, ValueError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"BUILD FAILED: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stderr or "", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
