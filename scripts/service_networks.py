"""Strict service-owned CIDR inputs, independent of the domain dataset and DNS."""
from __future__ import annotations

import datetime as dt
import ipaddress
import json


class ServiceNetworkError(ValueError):
    pass


# Conservative exclusions for special-purpose space, including protocol anycasts.
# Test overlap: Network.is_global alone only classifies its boundary addresses.
SPECIAL_NETWORKS = {
    4: [ipaddress.ip_network(n) for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")],
    6: [ipaddress.ip_network(n) for n in ("2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20")],
}


def normalize_networks(networks):
    """Merge exact unions only, never approximate or widen the address space."""
    networks = list(networks)
    return [network for version in (4, 6)
            for network in ipaddress.collapse_addresses(n for n in networks if n.version == version)]


def coverage(networks):
    networks = normalize_networks(networks)
    return {"total_prefixes": len(networks),
            **{f"ipv{version}_prefixes": sum(n.version == version for n in networks) for version in (4, 6)},
            **{f"ipv{version}_addresses": sum(n.num_addresses for n in networks if n.version == version) for version in (4, 6)}}


def parse_networks(path, source, *, values=None):
    if values is None and source["format"] != "cidr-lines":
        raise ServiceNetworkError("Unsupported service network format")
    networks, records = set(), 0
    for line in (values if values is not None else path.read_text(encoding="utf-8-sig").splitlines()):
        if not isinstance(line, str):
            raise ServiceNetworkError("Service prefix must be a string")
        value = line.strip()
        if not value or value.startswith(("#", "//")):
            continue
        records += 1
        try:
            if "/" not in value:
                raise ValueError("CIDR prefix is required")
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ServiceNetworkError(f"Invalid CIDR in {source['id']}: {value[:120]}") from exc
        # is_global alone includes multicast in Python's IP classification.
        if (not network.is_global or network.is_multicast or network.is_reserved
                or network.is_loopback or network.is_link_local or network.is_unspecified
                or any(network.overlaps(special) for special in SPECIAL_NETWORKS[network.version])
                or (network.version == 6 and not network.subnet_of(ipaddress.ip_network("2000::/3")))
                or network.prefixlen < source[f"min_ipv{network.version}_prefix_length"]):
            raise ServiceNetworkError(f"Non-public or overly broad network in {source['id']}: {network}")
        networks.add(network)
    if not source["min_entries"] <= len(networks) <= source["max_entries"]:
        raise ServiceNetworkError(f"Unexpected service network count in {source['id']}: {len(networks)}")
    for version in (4, 6):
        if sum(n.version == version for n in networks) < source[f"min_ipv{version}_entries"]:
            raise ServiceNetworkError(f"Missing or incomplete IPv{version} coverage in {source['id']}")
    raw_prefixes = [str(n) for n in sorted(networks, key=lambda n: (n.version, int(n.network_address), n.prefixlen))]
    normalized = normalize_networks(networks)
    stats = coverage(normalized)
    for version in (4, 6):
        if stats[f"ipv{version}_addresses"] > source[f"max_ipv{version}_addresses"]:
            raise ServiceNetworkError(f"Service IPv{version} address-space limit exceeded: {source['id']}")
    return normalized, {"records": records, "unique_conditions": len(networks),
                        "duplicate_records": records - len(networks), "invalid": 0,
                        "prefixes": [str(n) for n in normalized], "raw_prefixes": raw_prefixes, **stats}


def intersection_size(left, right):
    return sum(int(min(a.broadcast_address, b.broadcast_address))
               - int(max(a.network_address, b.network_address)) + 1
               for a in left for b in right if a.version == b.version and a.overlaps(b))


def validate_previous_services(previous, sources, policy):
    previous = previous.get("service_networks") if previous else None
    if previous is None:
        return {"baseline": "first-service-build", "warnings": []}
    old_sources = {source["id"]: source for source in previous["sources"]}
    if set(old_sources) != {source["id"] for source in sources}:
        raise ServiceNetworkError("Service source composition changed; explicit baseline review required")
    for current in sources:
        old = old_sources[current["id"]]
        if old["url"] != current["url"]:
            raise ServiceNetworkError("Service source URL changed; explicit baseline review required")
        before = [ipaddress.ip_network(n) for n in old["prefixes"]]
        after = [ipaddress.ip_network(n) for n in current["prefixes"]]
        for version in (4, 6):
            left, right = ([n for n in group if n.version == version] for group in (before, after))
            size = sum(n.num_addresses for n in left)
            new_size = sum(n.num_addresses for n in right)
            intersection = intersection_size(left, right)
            # Coverage changes catch same-count swaps, not just prefix-count drift.
            if (not size or size - intersection > size * policy["max_drop_fraction"]
                    or new_size - intersection > size * policy["max_growth_fraction"]):
                raise ServiceNetworkError(f"Unexpected IPv{version} service coverage change: {current['id']}")
        before_count, after_count = len(before), len(after)
        if not (before_count * (1 - policy["max_drop_fraction"]) <= after_count
                <= before_count * (1 + policy["max_growth_fraction"])):
            raise ServiceNetworkError(f"Unexpected service prefix-count change: {current['id']}")
    return {"baseline": "previous-service-build", "warnings": []}


def parse_ripe_source(source, fetched):
    path, metadata = fetched[source["id"]]
    identity_path, identity_metadata = fetched[source["identity_source"]["id"]]
    response = json.loads(path.read_text(encoding="utf-8-sig"))
    identity_response = json.loads(identity_path.read_text(encoding="utf-8-sig"))
    if not isinstance(response, dict) or not isinstance(identity_response, dict):
        raise ServiceNetworkError("RIPE response must be an object")
    data, identity = response.get("data", {}), identity_response.get("data", {})
    if not isinstance(data, dict) or not isinstance(identity, dict):
        raise ServiceNetworkError("RIPE data must be an object")
    if (response.get("status") != "ok" or identity_response.get("status") != "ok"
            or str(data.get("resource")) != str(source["asn"])
            or str(identity.get("resource")) != str(source["asn"])
            or identity.get("holder") != source["expected_holder"] or identity.get("announced") is not True
            or data.get("types") != ["o"] or set(data.get("af", [])) != {"v4", "v6"}
            or data.get("list_prefixes") is not True):
        raise ServiceNetworkError(f"RIPE resource or service identity verification failed: {source['id']}")
    # Fetch time is fixed in hashed metadata, making offline replay reproducible.
    for snapshot, evidence in ((data.get("query_time"), metadata),
                               (identity.get("query_endtime"), identity_metadata)):
        if not isinstance(snapshot, str):
            raise ServiceNetworkError("RIPE snapshot time is missing")
        moment = dt.datetime.fromisoformat(snapshot)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=dt.UTC)
        age = (dt.datetime.fromisoformat(evidence["fetched_at"]) - moment).total_seconds() / 3600
        if not -1 <= age <= source["max_snapshot_age_hours"]:
            raise ServiceNetworkError(f"RIPE snapshot is stale or in the future: {source['id']}")
    values = []
    for af, version in (("v4", 4), ("v6", 6)):
        prefixes = data.get("prefixes", {}).get(af, {}).get("originating")
        count = data.get("counts", {}).get(af, {}).get("originating")
        if (not isinstance(prefixes, list) or type(count) is not int or count != len(prefixes)
                or any(not isinstance(p, str) or ipaddress.ip_network(p, strict=True).version != version for p in prefixes)):
            raise ServiceNetworkError(f"RIPE prefix inventory is inconsistent: {source['id']}")
        values.extend(prefixes)
    networks, parsed = parse_networks(path, source, values=values)
    return networks, dict(parsed, asn=source["asn"], snapshot_at=data["query_time"],
                           identity=dict(identity_metadata, holder=identity["holder"]))


def prepare_services(fetched, config, previous):
    if config.get("schema_version") != 1 or not config.get("sources"):
        raise ServiceNetworkError("Missing service source configuration")
    ids = [s["id"] for s in config["sources"]]
    if len(set(ids)) != len(ids):
        raise ServiceNetworkError("Duplicate service source ID")
    all_networks, stats = [], []
    for source in config["sources"]:
        path, fetched_metadata = fetched[source["id"]]
        if source["format"] == "ripe-ris-prefixes":
            networks, parsed = parse_ripe_source(source, fetched)
        else:
            networks, parsed = parse_networks(path, source)
        all_networks.extend(networks)
        stats.append(dict(fetched_metadata, **parsed, service=source["service"],
                          description=source["description"], reference=source["reference"]))
    validation = validate_previous_services(previous, stats, config["validation"])
    networks = normalize_networks(all_networks)
    return networks, {"sources": stats, "validation": validation, "output": coverage(networks)}


def restore_services(previous, config, max_stale_hours, now=None):
    if not previous or not isinstance(previous.get("service_networks"), dict):
        raise ServiceNetworkError("Service download failed and no previous complete service set is available")
    previous_services = previous["service_networks"]
    built_at = dt.datetime.fromisoformat(previous["built_at"])
    current_time = now or dt.datetime.now(dt.UTC)
    age = (current_time - built_at).total_seconds() / 3600
    if not 0 <= age <= max_stale_hours:
        raise ServiceNetworkError("Previous complete service set is too old for stale fallback")
    old_sources = {source["id"]: source for source in previous_services.get("sources", [])}
    if set(old_sources) != {source["id"] for source in config["sources"]}:
        raise ServiceNetworkError("Service source composition changed; stale fallback is forbidden")
    all_networks, stats = [], []
    for source in config["sources"]:
        old = old_sources[source["id"]]
        if old.get("url") != source["url"]:
            raise ServiceNetworkError("Service source URL changed; stale fallback is forbidden")
        networks, _ = parse_networks(None, source, values=old["prefixes"])
        all_networks.extend(networks)
        stats.append(old)
    networks = normalize_networks(all_networks)
    return networks, {
        "sources": stats,
        "validation": {
            "baseline": "previous-service-data-stale",
            "warnings": [],
            "restored_from_built_at": previous["built_at"],
            "stale_hours": round(age, 2),
        },
        "output": coverage(networks),
    }
