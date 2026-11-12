"""Build domain and reviewed service-network VPN rule sets. No router access."""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import datetime as dt
import hashlib
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
from report import make_report
from service_networks import normalize_networks, parse_networks, prepare_services, restore_services

ROOT = Path(__file__).resolve().parents[1]
USER_AGENT = "Routing/2 (public routing data only)"
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


def parse_source(path, source, max_invalid_fraction, ip_networks=None):
    exact, suffix, source_ips = set(), set(), set()
    invalid, samples, records, ip_records = 0, [], 0, 0
    invalid_reasons = collections.Counter()

    def reject(value, reason):
        nonlocal invalid
        invalid += 1
        invalid_reasons[reason] += 1
        if len(samples) < 30:
            samples.append({"value": str(value)[:200], "reason": reason})

    def accept(value, kind):
        nonlocal records, ip_records
        records += 1
        if kind == "domain_suffix" and isinstance(value, str):
            try:
                address = ipaddress.ip_address(value.strip())
            except ValueError:
                pass
            else:
                if not address.is_global:
                    reject(value, "non-public IP address")
                    return
                source_ips.add(ipaddress.ip_network(f"{address}/{address.max_prefixlen}"))
                ip_records += 1
                return
        try:
            name = normalize_domain(value)
        except ValueError as exc:
            reject(value, str(exc))
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
    if ip_networks is not None:
        ip_networks.update(source_ips)
    return exact, suffix, {
        "unique_conditions": count, "exact": len(exact), "suffix": len(suffix),
        "records": records, "invalid": invalid, "invalid_samples": samples,
        "invalid_by_reason": dict(sorted(invalid_reasons.items())),
        "ip_records": ip_records, "ip_addresses": len(source_ips),
        "duplicate_records": records - invalid - ip_records - count,
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


def read_manual_rules(path, psl, *, require_review=False, allow_ip=False, now=None):
    data = read_json(path)
    if data.get("schema_version") != 1 or not isinstance(data.get("rules"), list):
        raise BuildError(f"Unexpected manual rule schema: {path.name}")
    exact, suffix, ip_rules, records = {}, {}, [], []
    for item in data["rules"]:
        if not isinstance(item, dict) or set(item) - {"kind", "domain", "reason", "review_after"}:
            raise BuildError(f"Unexpected manual rule fields in {path.name}")
        kind = item.get("kind")
        if (kind not in {"domain", "domain_suffix", "ip_cidr"} or not isinstance(item.get("reason"), str)
                or not item["reason"].strip()):
            raise BuildError(f"Manual rule kind and reason are required in {path.name}")
        if require_review:
            try:
                review_after = dt.date.fromisoformat(item.get("review_after", ""))
            except ValueError as exc:
                raise BuildError(f"Direct exception review_after must be an ISO date in {path.name}") from exc
            current_date = now or dt.datetime.now(dt.timezone.utc).date()
            if review_after < current_date:
                raise BuildError(f"Direct exception review is overdue: {item['domain']} ({review_after})")
        if kind == "ip_cidr":
            if not allow_ip:
                raise BuildError(f"IP rules are supported only for Direct exceptions: {path.name}")
            network = ipaddress.ip_network(item["domain"], strict=True)
            if not network.is_global or network.prefixlen != network.max_prefixlen:
                raise BuildError(f"Direct IP exceptions must be public exact /32 or /128 addresses: {network}")
            if network in ip_rules:
                raise BuildError(f"Duplicate manual rule: {network}")
            ip_rules.append(network)
            records.append({**item, "kind": kind, "domain": str(network)})
            continue
        name = normalize_domain(item.get("domain"))
        if kind == "domain_suffix" and psl.is_broad_routing_suffix(name):
            raise BuildError(f"Manual public-suffix rule is forbidden: {name}")
        target = exact if kind == "domain" else suffix
        if name in exact or name in suffix:
            raise BuildError(f"Duplicate manual rule: {name}")
        target[name] = dict(item)
        records.append({**item, "kind": kind, "domain": name})
    return exact, suffix, ip_rules, records


def domain_groups(data):
    groups = {"domain": set(), "domain_suffix": set()}
    if set(data) != {"version", "rules"} or not isinstance(data["rules"], list):
        raise BuildError("Unexpected domain rule-set for semantic diff")
    for rule in data["rules"]:
        if not isinstance(rule, dict) or set(rule) - groups.keys():
            raise BuildError("Non-domain condition in semantic diff baseline")
        for kind, values in rule.items():
            if not isinstance(values, list):
                raise BuildError("Unexpected domain list in semantic diff baseline")
            groups[kind].update(values)
    return groups


def make_domain_diff(previous_rules, exact, suffix, original_exact, original_suffix, sources, limit=1000):
    current = {"domain": set(exact), "domain_suffix": set(suffix)}
    if previous_rules is None:
        previous = {"domain": set(), "domain_suffix": set()}
        baseline = "first-build"
    else:
        previous = domain_groups(previous_rules)
        baseline = "previous-successful-or-approved-manifest"
    changes = {"baseline": baseline, "observed_at": utc_now(), "sample_limit": limit, "by_kind": {}}
    for kind in ("domain", "domain_suffix"):
        added = sorted(current[kind] - previous[kind])
        removed = sorted(previous[kind] - current[kind])
        changes["by_kind"][kind] = {
            "added": len(added), "removed": len(removed),
            "added_sample": added[:limit], "removed_sample": removed[:limit],
        }
    added_names = set().union(*(set(current[kind]) - set(previous[kind]) for kind in current))
    masks = collections.Counter()
    for name in added_names:
        mask = original_exact.get(name, 0) | original_suffix.get(name, 0)
        for parent in parents(name):
            mask |= original_suffix.get(parent, 0)
        masks[mask] += 1
    changes["added_by_sources"] = [
        {"sources": [source["id"] for i, source in enumerate(sources) if mask & (1 << i)], "conditions": amount}
        for mask, amount in sorted(masks.items())
    ]
    changes["total_added"] = sum(item["added"] for item in changes["by_kind"].values())
    changes["total_removed"] = sum(item["removed"] for item in changes["by_kind"].values())
    previous_names = previous["domain"] | previous["domain_suffix"]
    current_names = current["domain"] | current["domain_suffix"]
    uncovered_removed = sorted(name for name in previous_names if not match_rule(name, current["domain"], current["domain_suffix"]))
    newly_covered = sorted(name for name in current_names if not match_rule(name, previous["domain"], previous["domain_suffix"]))
    changes["effective_added"] = len(newly_covered)
    changes["effective_removed"] = len(uncovered_removed)
    changes["effective_added_sample"] = newly_covered[:limit]
    changes["effective_removed_sample"] = uncovered_removed[:limit]
    return changes


def exact_networks(networks):
    return sorted(set(networks), key=lambda n: (n.version, int(n.network_address), n.prefixlen))


def validate_registry(previous, networks, policy, now=None, section="registry_ip"):
    current = {str(network) for network in networks}
    registry = previous.get(section) if previous else None
    if not registry:
        return {"baseline": "first-registry-build", "warnings": []}
    source_ids = {source.get("id") for source in registry.get("sources", [])}
    if section == "registry_ip" and previous.get("registry_cidr") is None and source_ids == {"antifilter-full", "refilter"}:
        return {"baseline": "first-registry-build", "warnings": []}
    old = set(registry["output"]["prefixes"])
    removed, added = old - current, current - old
    limits = policy["validation"]["registry_ip"]
    if len(removed) > len(old) * limits["max_drop_fraction"] or len(added) > len(old) * limits["max_growth_fraction"]:
        raise BuildError(f"Unexpected registry IP coverage change: +{len(added)} -{len(removed)}")
    return {"baseline": "previous-registry-build", "warnings": [],
            "added": len(added), "removed": len(removed)}


def compile_and_verify(directory, executable, source_format_version, basename="blocked-domains", networks_only=False):
    version = subprocess.run([str(executable), "version"], capture_output=True, text=True, check=True, timeout=15).stdout.splitlines()[0]
    source, binary, decoded = (directory / name for name in (basename + ".json", basename + ".srs", "roundtrip.json"))
    subprocess.run([str(executable), "rule-set", "compile", "--output", str(binary), str(source)], check=True, capture_output=True, text=True, timeout=180)
    subprocess.run([str(executable), "rule-set", "decompile", "--output", str(decoded), str(binary)], check=True, capture_output=True, text=True, timeout=180)
    original, result = read_json(source), read_json(decoded)
    def conditions(data):
        if networks_only:
            networks = []
            for rule in data.get("rules", []):
                if set(rule) != {"ip_cidr"} or not isinstance(rule["ip_cidr"], list) or not rule["ip_cidr"]:
                    raise BuildError("Compiler roundtrip introduced a non-CIDR or empty condition")
                networks.extend(ipaddress.ip_network(n, strict=True) for n in rule["ip_cidr"])
            return normalize_networks(networks)
        groups = {"domain": set(), "domain_suffix": set(), "ip_cidr": set()}
        for rule in data.get("rules", []):
            if set(rule) - groups.keys():
                raise BuildError("Compiler roundtrip introduced a non-domain condition")
            for kind, values in rule.items():
                if isinstance(values, str):
                    values = [values]
                if kind == "ip_cidr":
                    groups[kind].update(normalize_networks(ipaddress.ip_network(n, strict=True) for n in values))
                else:
                    groups[kind].update(values)
        return groups
    if conditions(original) != conditions(result):
        raise BuildError("SRS compile/decompile changed the routing conditions")
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


def build(args):
    started = time.monotonic()
    root = Path(args.root).resolve()
    sources_config = read_json(root / "config/sources.json")
    service_config = read_json(root / "config/service-networks.json")
    registry_config = read_json(root / "config/registry-ip-sources.json")
    policy = read_json(root / "config/policy.json")
    previous = read_json(args.previous) if args.previous else None
    sources = sources_config["sources"]
    psl_source = sources_config["public_suffix_list"]
    domain_inputs = sources + [psl_source]
    registry_inputs = registry_config["sources"]
    service_inputs = service_config["sources"] + [s["identity_source"] for s in service_config["sources"] if "identity_source" in s]
    all_sources = domain_inputs + registry_inputs + service_inputs
    if len({s["id"] for s in all_sources}) != len(all_sources):
        raise BuildError("Duplicate input source ID")
    cache = root / "cache/sources"
    fetched, service_errors = {}, {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = {s["id"]: pool.submit(fetch_source, s, cache, args.offline) for s in all_sources}
        for key, future in futures.items():
            try:
                fetched[key] = future.result()
            except BuildError as exc:
                if key in {s["id"] for s in domain_inputs}:
                    raise
                service_errors[key] = str(exc)
    if args.fetch_only:
        if service_errors:
            raise BuildError(f"Cannot cache every service input: {service_errors}")
        print("All required public inputs cached and hashed. No compilation performed.")
        return
    if service_errors:
        if args.offline:
            raise BuildError(f"Offline replay is missing service inputs: {sorted(service_errors)}")
        try:
            service_networks, service_manifest = restore_services(
                previous, service_config, policy["validation"]["max_service_stale_hours"])
        except ValueError as exc:
            raise BuildError(f"Service download failed and stale fallback is unavailable: {service_errors}; {exc}") from exc
        service_manifest["validation"]["fetch_errors"] = service_errors
    else:
        service_networks, service_manifest = prepare_services(fetched, service_config, previous)
    psl = PublicSuffixes(fetched[psl_source["id"]][0].read_text(encoding="utf-8-sig"))
    if psl.count < psl_source["min_entries"]:
        raise BuildError("Public Suffix List is unexpectedly small")
    manual_exact, manual_suffix, _, manual_records = read_manual_rules(root / "config/manual-vpn.json", psl)
    direct_exact, direct_suffix, direct_ip_rules, direct_records = read_manual_rules(
        root / "config/direct-exceptions.json", psl, require_review=True, allow_ip=True)
    exact, suffix, exclusions = {}, {}, {}
    core_exact, core_suffix = {}, {}
    core_excluded = set(sources_config.get("core_excluded_sources", []))
    stats, total_conditions, skipped = [], 0, 0
    domain_registry_ips = []
    shared = {normalize_domain(name): reason for name, reason in policy["shared_roots"].items()}
    service_owned = {normalize_domain(name) for name in policy.get("service_owned_suffixes", {})}
    if shared.keys() & service_owned:
        raise BuildError("A domain cannot be both shared infrastructure and a service-owned exception")
    for i, source in enumerate(sources):
        source_ips = set()
        source_exact, source_suffix, parsed = parse_source(
            fetched[source["id"]][0], source, policy["validation"]["max_invalid_fraction"], source_ips)
        for network in source_ips:
            domain_registry_ips.append((network, 1 << i))
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
        if source["id"] not in core_excluded:
            for kind, names, merged in (("domain", source_exact, core_exact), ("domain_suffix", source_suffix, core_suffix)):
                for name in names:
                    if not exclusion_reason(kind, name, shared, psl, service_owned):
                        merged[name] = merged.get(name, 0) | (1 << i)
        metadata["filtered_conditions"] = rejected_here
        stats.append(metadata)
        skipped += rejected_here
        print(f"Parsed {source['id']}: {parsed['unique_conditions']:,} conditions, "
              f"{parsed['ip_addresses']} exact IPs, {rejected_here} broad rules excluded", flush=True)
    manual_mask = 1 << len(sources)
    for kind, names, merged in (("domain", manual_exact, exact), ("domain_suffix", manual_suffix, suffix)):
        for name in names:
            merged[name] = merged.get(name, 0) | manual_mask
    for kind, names, merged in (("domain", manual_exact, core_exact), ("domain_suffix", manual_suffix, core_suffix)):
        for name in names:
            merged[name] = merged.get(name, 0) | manual_mask
    total_conditions += len(manual_exact) + len(manual_suffix)
    sources_with_manual = sources + [{"id": "manual-vpn"}]
    before_minimize = len(exact) + len(suffix)
    original_exact, original_suffix = exact, suffix
    exact, suffix = minimize(original_exact, original_suffix)
    core_exact, core_suffix = minimize(core_exact, core_suffix)
    if len(core_exact) + len(core_suffix) < 1000:
        raise BuildError("Compact domain set is unexpectedly small")
    count = len(exact) + len(suffix)
    if count < policy["validation"]["minimum_output_domains"]:
        raise BuildError(f"Unexpectedly small final set: {count}")
    for name in suffix:
        if name not in manual_suffix and exclusion_reason("domain_suffix", name, shared, psl, service_owned):
            raise BuildError("Broad rule survived filtering")
    for names in (original_exact, original_suffix):
        if any(not match_rule(name, exact, suffix) for name in names):
            raise BuildError("Minimization lost an input condition")
    validation = validate_previous(previous, stats, count, policy)
    registry_by_network, registry_cidr_by_network = {}, {}
    registry_source_stats = []
    for i, source in enumerate(registry_config["sources"]):
        _, parsed = parse_networks(fetched[source["id"]][0], source)
        exact_count, cidr_count = 0, 0
        for network in map(ipaddress.ip_network, parsed["raw_prefixes"]):
            if network.prefixlen == network.max_prefixlen:
                registry_by_network[network] = registry_by_network.get(network, 0) | (1 << i)
                exact_count += 1
            else:
                registry_cidr_by_network[network] = registry_cidr_by_network.get(network, 0) | (1 << i)
                cidr_count += 1
        registry_source_stats.append(dict(fetched[source["id"]][1], **parsed,
                                          exact_prefixes=exact_count, cidr_prefixes=cidr_count,
                                          description=source["description"]))
    for network, mask in domain_registry_ips:
        registry_by_network[network] = registry_by_network.get(network, 0) | mask
    registry_networks = exact_networks(registry_by_network)
    registry_cidr_networks = normalize_networks(registry_cidr_by_network)
    if not 1 <= len(registry_networks) <= policy["validation"]["maximum_registry_ips"]:
        raise BuildError(f"Unexpected registry IP count: {len(registry_networks)}")
    if any(network.prefixlen != network.max_prefixlen for network in registry_networks):
        raise BuildError("Registry IP set may contain only exact /32 and /128 addresses")
    registry_validation = validate_registry(previous, registry_networks, policy)
    registry_cidr_validation = validate_registry(previous, registry_cidr_networks, policy, section="registry_cidr")
    probe_config = read_json(root / "config/probes.json")
    expectations = probe_config.get("expectations", {})
    probes = []
    for domain in probe_config["domains"]:
        name = normalize_domain(domain)
        match = match_rule(name, exact, suffix)
        direct_match = match_rule(name, direct_exact, direct_suffix)
        mask = original_exact.get(name, 0) | original_suffix.get(name, 0)
        for parent in parents(name):
            mask |= original_suffix.get(parent, 0)
        final_decision = "Direct" if direct_match else ("VPN" if match else "Direct")
        expected = expectations.get(name)
        if expected is not None and expected not in {"VPN", "Direct"}:
            raise BuildError(f"Unexpected probe expectation for {name}: {expected}")
        if expected is not None and final_decision != expected:
            raise BuildError(f"Probe regression for {name}: expected {expected}, got {final_decision}")
        probes.append({"domain": name, "base_decision": "VPN" if match else "Direct",
                       "final_decision": final_decision, "expected": expected,
                       "matched_type": match[0] if match else None, "matched_rule": match[1] if match else None,
                       "direct_exception": direct_match[1] if direct_match else None,
                       "sources": [s["id"] for i, s in enumerate(sources_with_manual) if mask & (1 << i)]})
    lock = read_json(root / "config/tools-lock.json")
    compiler = Path(args.sing_box).resolve() if args.sing_box else root / ".tools" / ("sing-box.exe" if os.name == "nt" else "sing-box")
    if not compiler.is_file():
        raise BuildError("Compiler missing. Run scripts/install_tools.py first.")
    previous_rules = read_json(args.previous_rules) if args.previous_rules else None
    if previous_rules is None and args.previous:
        previous_rules_path = Path(args.previous).with_name("blocked-domains.json")
        if previous_rules_path.is_file():
            previous_rules = read_json(previous_rules_path)
    domain_diff = make_domain_diff(previous_rules, exact, suffix, original_exact, original_suffix, sources_with_manual)
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
        core_rules = {}
        if core_exact:
            core_rules["domain"] = sorted(core_exact)
        if core_suffix:
            core_rules["domain_suffix"] = sorted(core_suffix)
        write_json(stage / "blocked-domains-core.json", {"version": lock["source_format_version"], "rules": [core_rules]})
        with (stage / "blocked-domains-core.txt").open("w", encoding="utf-8", newline="\n") as stream:
            for name in sorted(core_exact):
                stream.write("full:" + name + "\n")
            for name in sorted(core_suffix):
                stream.write("domain:" + name + "\n")
        core_compilation = compile_and_verify(stage, compiler, lock["source_format_version"], "blocked-domains-core")
        write_json(stage / "blocked-services-ip.json", {"version": lock["source_format_version"],
                                                       "rules": [{"ip_cidr": [str(n) for n in service_networks]}]})
        (stage / "blocked-services-ip.txt").write_text("".join(str(n) + "\n" for n in service_networks), encoding="utf-8")
        service_manifest["compiler"] = compile_and_verify(stage, compiler, lock["source_format_version"],
                                                          "blocked-services-ip", networks_only=True)
        service_manifest["output"]["srs_bytes"] = (stage / "blocked-services-ip.srs").stat().st_size
        write_json(stage / "blocked-registry-ip.json", {"version": lock["source_format_version"],
                                                       "rules": [{"ip_cidr": [str(n) for n in registry_networks]}]})
        (stage / "blocked-registry-ip.txt").write_text("".join(str(n) + "\n" for n in registry_networks), encoding="utf-8")
        registry_compiler = compile_and_verify(stage, compiler, lock["source_format_version"],
                                               "blocked-registry-ip", networks_only=True)
        write_json(stage / "blocked-registry-ip-cidr.json", {"version": lock["source_format_version"],
                                                            "rules": [{"ip_cidr": [str(n) for n in registry_cidr_networks]}]})
        (stage / "blocked-registry-ip-cidr.txt").write_text(
            "".join(str(n) + "\n" for n in registry_cidr_networks), encoding="utf-8")
        registry_cidr_compiler = compile_and_verify(stage, compiler, lock["source_format_version"],
                                                    "blocked-registry-ip-cidr", networks_only=True)
        direct_rules = {}
        if direct_exact:
            direct_rules["domain"] = sorted(direct_exact)
        if direct_suffix:
            direct_rules["domain_suffix"] = sorted(direct_suffix)
        if direct_ip_rules:
            direct_rules["ip_cidr"] = [str(n) for n in normalize_networks(direct_ip_rules)]
        write_json(stage / "routing-direct-exceptions.json", {
            "version": lock["source_format_version"], "rules": [direct_rules] if direct_rules else []})
        direct_lines = ["full:" + name for name in sorted(direct_exact)]
        direct_lines += ["domain:" + name for name in sorted(direct_suffix)]
        direct_lines += [str(n) for n in normalize_networks(direct_ip_rules)]
        (stage / "routing-direct-exceptions.txt").write_text("".join(line + "\n" for line in direct_lines), encoding="utf-8")
        direct_compiler = compile_and_verify(stage, compiler, lock["source_format_version"], "routing-direct-exceptions")
        excluded = [exclusions[key] for key in sorted(exclusions)]
        write_json(stage / "excluded.json", excluded)
        write_json(stage / "probes.json", probes)
        write_json(stage / "domain-changes.json", domain_diff)
        write_json(stage / "manual-rules.json", {"vpn": manual_records, "direct_exceptions": direct_records})
        recipe_paths = list((root / "config").glob("*.json")) + list((root / "scripts").glob("*.py")) + [root / "requirements.txt", root / ".github/workflows/build.yml"]
        config_hashes = {str(path.relative_to(root)).replace(os.sep, "/"): file_sha256(path) for path in sorted(recipe_paths)}
        source_bits = collections.Counter(mask for mask in original_exact.values())
        source_bits.update(original_suffix.values())
        intersections = []
        for mask, amount in sorted(source_bits.items()):
            intersections.append({"sources": [s["id"] for i, s in enumerate(sources_with_manual) if mask & (1 << i)],
                                  "unique_conditions": amount})
        registry_output = {
            "total_prefixes": len(registry_networks),
            "ipv4_prefixes": sum(n.version == 4 for n in registry_networks),
            "ipv6_prefixes": sum(n.version == 6 for n in registry_networks),
            "prefixes": [str(n) for n in registry_networks],
            "srs_bytes": (stage / "blocked-registry-ip.srs").stat().st_size,
        }
        registry_cidr_output = {
            "total_prefixes": len(registry_cidr_networks),
            "ipv4_prefixes": sum(n.version == 4 for n in registry_cidr_networks),
            "ipv6_prefixes": sum(n.version == 6 for n in registry_cidr_networks),
            "prefixes": [str(n) for n in registry_cidr_networks],
            "srs_bytes": (stage / "blocked-registry-ip-cidr.srs").stat().st_size,
        }
        core_output = {"total_conditions": len(core_exact) + len(core_suffix),
                       "exact": len(core_exact), "suffix": len(core_suffix),
                       "source_ids": [s["id"] for s in sources if s["id"] not in core_excluded] + ["manual-vpn"],
                       "srs_bytes": (stage / "blocked-domains-core.srs").stat().st_size}
        built_at = utc_now()
        repository = os.environ.get("GITHUB_REPOSITORY", "Vanilla-SilQ-HD/Routing")
        release_base = f"https://github.com/{repository}/releases/latest/download/"
        catalog_names = ["blocked-domains", "blocked-domains-core", "blocked-services-ip",
                         "blocked-registry-ip", "blocked-registry-ip-cidr", "routing-direct-exceptions"]
        write_json(stage / "catalog.json", {"generated": built_at, "sources": [
            {"id": "routing", "url": release_base + "{}", "names": catalog_names}
        ]})
        write_json(stage / "presets.user.json", make_presets(release_base))
        built_at = utc_now()
        write_json(stage / "status.json", {"schemaVersion": 1, "label": "domains",
                                           "message": f"{count:,}".replace(",", " "), "color": "brightgreen"})
        write_json(stage / "updated.json", {"schemaVersion": 1, "label": "updated",
                                            "message": built_at.replace("T", " "), "color": "blue"})
        output_files = [path.name for path in stage.iterdir() if path.is_file()]
        manifest = {
            "schema_version": 1, "built_at": built_at, "offline_replay": args.offline,
            "sources": stats, "public_suffix_list": dict(fetched[psl_source["id"]][1], parsed_rules=psl.count),
            "service_networks": service_manifest,
            "core": {"output": core_output, "compiler": core_compilation},
            "registry_ip": {"sources": [{"id": s["id"], "ip_addresses": s["ip_addresses"]} for s in stats if s["ip_addresses"]]
                                       + [{key: value for key, value in source.items() if key not in {"prefixes", "raw_prefixes"}}
                                          for source in registry_source_stats],
                            "output": registry_output, "validation": registry_validation, "compiler": registry_compiler},
            "registry_cidr": {"sources": registry_source_stats, "output": registry_cidr_output,
                              "validation": registry_cidr_validation, "compiler": registry_cidr_compiler},
            "direct_exceptions": {"rules": direct_records, "compiler": direct_compiler,
                                  "output": {"total_conditions": len(direct_exact) + len(direct_suffix) + len(direct_ip_rules),
                                             "prefixes": [str(n) for n in normalize_networks(direct_ip_rules)],
                                             "srs_bytes": (stage / "routing-direct-exceptions.srs").stat().st_size}},
            "manual_vpn": {"rules": manual_records},
            "domain_diff": {"added": domain_diff["total_added"], "removed": domain_diff["total_removed"],
                            "effective_added": domain_diff["effective_added"],
                            "effective_removed": domain_diff["effective_removed"]},
            "domain_changes": domain_diff,
            "configuration_sha256": config_hashes, "compiler": compilation,
            "environment": {"python": sys.version.split()[0], "idna": idna.__version__,
                            "github_commit": os.environ.get("GITHUB_SHA"),
                            "repository": os.environ.get("GITHUB_REPOSITORY", "Vanilla-SilQ-HD/Routing")},
            "counts": {"source_unique_conditions_sum": total_conditions, "filtered_source_conditions_sum": skipped,
                       "unique_filtered_conditions": before_minimize,
                       "duplicate_conditions_across_sources": total_conditions - skipped - before_minimize,
                       "redundant_conditions_removed": before_minimize - count},
            "exact_intersections_before_minimization": intersections,
            "output": {"total_conditions": count, "exact": len(exact), "suffix": len(suffix),
                       "srs_bytes": (stage / "blocked-domains.srs").stat().st_size,
                       "files": {name: file_sha256(stage / name) for name in output_files}},
            "validation": validation, "elapsed_seconds": round(time.monotonic() - started, 2),
            "scope": {"domains_only": False, "personal_rules_included": False, "router_access": False,
                      "broad_ai_category_included": False, "ru_direct_category_included": False,
                      "ip_rules_included": True, "registry_ip_rules_included": True,
                      "direct_exceptions_included": True, "dns_configuration_included": False},
        }
        write_json(stage / "manifest.json", manifest)
        (stage / "report.html").write_text(make_report(manifest, excluded, probes), encoding="utf-8")
        (stage / "SHA256SUMS").write_text("".join(f"{file_sha256(path)}  {path.name}\n" for path in sorted(stage.iterdir()) if path.is_file()), encoding="utf-8")
        if target.exists():
            target.rmdir()
        stage.rename(target)
    print(json.dumps({"output": str(target), "domains": count, "service_networks": service_manifest["output"],
                      "registry_ip": registry_output, "direct_exceptions": len(direct_records),
                      "srs_bytes": manifest["output"]["srs_bytes"], "excluded_broad_conditions": len(excluded),
                      "validation": compilation}, ensure_ascii=False), flush=True)


def make_presets(release_base):
    rule_urls = {
        "routing": "blocked-domains.srs",
        "routing-core": "blocked-domains-core.srs",
        "routing-services": "blocked-services-ip.srs",
        "routing-registry-ip": "blocked-registry-ip.srs",
        "routing-registry-ip-cidr": "blocked-registry-ip-cidr.srs",
    }
    specifications = [
        ("routing-full", "Routing · Full", ["routing", "routing-services", "routing-registry-ip"],
         "Полная доменная база и точные IP. Direct-исключения настройте отдельным приоритетным правилом."),
        ("routing-compact", "Routing · Compact", ["routing-core", "routing-services", "routing-registry-ip"],
         "Компактная доменная база без двух крупнейших реестров, сервисные сети и точные IP. Direct-исключения настраиваются отдельно."),
        ("routing-wide-cidr", "Routing · Wide CIDR", ["routing-registry-ip-cidr"],
         "Дополнительные широкие CIDR. Подключайте только после проверки покрытия."),
    ]
    presets = []
    for preset_id, name, tags, notice in specifications:
        presets.append({"id": preset_id, "name": name, "iconSlug": "router", "category": "custom",
                        "notice": notice, "engines": {"singbox": {
                            "ruleSets": [{"tag": tag, "url": release_base + rule_urls[tag]} for tag in tags],
                            "action": "tunnel"}}})
    return {"presets": presets}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--offline", action="store_true", help="Replay only SHA-256-verified cached inputs; no network")
    parser.add_argument("--fetch-only", action="store_true")
    parser.add_argument("--previous", help="Previous successful/approved manifest.json for drift guards")
    parser.add_argument("--previous-rules", help="Previous blocked-domains.json for the semantic diff")
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
