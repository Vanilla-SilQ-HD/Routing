"""Pure domain stages used by the build pipeline."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from routing.domains import PublicSuffixes, exclusion_reason, match_rule, minimize, normalize_domain
from routing.sources import SourceSet


@dataclass(frozen=True)
class ParsedSource:
    source: dict[str, Any]
    exact: set[str]
    suffix: set[str]
    ip_networks: set[Any]
    metadata: dict[str, Any]


@dataclass(frozen=True)
class ParsedDomains:
    sources: tuple[ParsedSource, ...]


@dataclass(frozen=True)
class DomainPolicy:
    exact: dict[str, int]
    suffix: dict[str, int]
    core_exact: dict[str, int]
    core_suffix: dict[str, int]
    exclusions: dict[tuple[str, str], dict[str, Any]]
    stats: list[dict[str, Any]]
    registry_ips: list[tuple[Any, int]]
    total_conditions: int
    skipped: int
    core_excluded: set[str]
    shared: dict[str, Any]
    service_owned: set[str]


@dataclass(frozen=True)
class DomainSets:
    exact: dict[str, int]
    suffix: dict[str, int]
    core_exact: dict[str, int]
    core_suffix: dict[str, int]
    smart_exact: dict[str, int]
    smart_suffix: dict[str, int]
    original_exact: dict[str, int]
    original_suffix: dict[str, int]
    popular: set[str]
    before_minimize: int
    count: int


def parse_domains(
    sources: list[dict[str, Any]],
    fetched: dict[str, Any],
    max_invalid_fraction: float,
    parse_source: Callable[..., tuple[set[str], set[str], dict[str, Any]]],
) -> ParsedDomains:
    parsed_sources = []
    for source in sources:
        ip_networks: set[Any] = set()
        exact, suffix, parsed = parse_source(fetched[source["id"]][0], source, max_invalid_fraction, ip_networks)
        metadata = dict(fetched[source["id"]][1], **parsed, description=source["description"])
        if "caveat" in source:
            metadata["caveat"] = source["caveat"]
        parsed_sources.append(ParsedSource(source, exact, suffix, ip_networks, metadata))
    return ParsedDomains(tuple(parsed_sources))


def apply_policy(
    parsed: ParsedDomains,
    sources_config: dict[str, Any],
    policy: dict[str, Any],
    psl: PublicSuffixes,
    manual_exact: dict[str, Any],
    manual_suffix: dict[str, Any],
) -> DomainPolicy:
    exact: dict[str, int] = {}
    suffix: dict[str, int] = {}
    core_exact: dict[str, int] = {}
    core_suffix: dict[str, int] = {}
    exclusions: dict[tuple[str, str], dict[str, Any]] = {}
    core_excluded = set(sources_config.get("core_excluded_sources", []))
    shared = {normalize_domain(name): reason for name, reason in policy["shared_roots"].items()}
    service_owned = {normalize_domain(name) for name in policy.get("service_owned_suffixes", {})}
    if shared.keys() & service_owned:
        raise ValueError("A domain cannot be both shared infrastructure and a service-owned exception")
    stats: list[dict[str, Any]] = []
    registry_ips: list[tuple[Any, int]] = []
    total_conditions = skipped = 0
    for i, item in enumerate(parsed.sources):
        source = item.source
        registry_ips.extend((network, SourceSet().add(i).mask) for network in item.ip_networks)
        metadata = dict(item.metadata)
        total_conditions += metadata["unique_conditions"]
        rejected_here = 0
        for kind, names, merged in (("domain", item.exact, exact), ("domain_suffix", item.suffix, suffix)):
            for name in names:
                reason = exclusion_reason(kind, name, shared, psl, service_owned)
                if reason:
                    key = (kind, name)
                    record = exclusions.setdefault(key, {"kind": kind, "domain": name, "reason": reason, "sources": []})
                    record["sources"].append(source["id"])
                    rejected_here += 1
                    continue
                merged[name] = SourceSet(merged.get(name, 0)).add(i).mask
        if source["id"] not in core_excluded:
            for kind, names, merged in (("domain", item.exact, core_exact), ("domain_suffix", item.suffix, core_suffix)):
                for name in names:
                    if not exclusion_reason(kind, name, shared, psl, service_owned):
                        merged[name] = SourceSet(merged.get(name, 0)).add(i).mask
        metadata["filtered_conditions"] = rejected_here
        stats.append(metadata)
        skipped += rejected_here
    manual_index = len(parsed.sources)
    for manual_names, merged in ((manual_exact, exact), (manual_suffix, suffix), (manual_exact, core_exact), (manual_suffix, core_suffix)):
        for name in manual_names:
            merged[name] = SourceSet(merged.get(name, 0)).add(manual_index).mask
    total_conditions += len(manual_exact) + len(manual_suffix)
    return DomainPolicy(
        exact, suffix, core_exact, core_suffix, exclusions, stats, registry_ips, total_conditions, skipped, core_excluded, shared, service_owned
    )


def minimize_domains(selected: DomainPolicy, psl: PublicSuffixes, popular: set[str], minimum_output_domains: int, manual_suffix: dict[str, Any]) -> DomainSets:
    original_exact, original_suffix = selected.exact, selected.suffix
    before_minimize = len(original_exact) + len(original_suffix)
    exact, suffix = minimize(original_exact, original_suffix)
    core_exact, core_suffix = minimize(selected.core_exact, selected.core_suffix)
    if len(core_exact) + len(core_suffix) < 1000:
        raise ValueError("Compact domain set is unexpectedly small")
    smart_exact, smart_suffix = dict(core_exact), dict(core_suffix)
    for name, mask in original_exact.items():
        if psl.registrable_domain(name) in popular:
            smart_exact[name] = smart_exact.get(name, 0) | mask
    for name, mask in original_suffix.items():
        if psl.registrable_domain(name) in popular:
            smart_suffix[name] = smart_suffix.get(name, 0) | mask
    smart_exact, smart_suffix = minimize(smart_exact, smart_suffix)
    for names in (core_exact, core_suffix):
        if any(not match_rule(name, smart_exact, smart_suffix) for name in names):
            raise ValueError("Smart set lost a Compact condition")
    count = len(exact) + len(suffix)
    if count < minimum_output_domains:
        raise ValueError(f"Unexpectedly small final set: {count}")
    for name in suffix:
        if name not in manual_suffix and exclusion_reason("domain_suffix", name, selected.shared, psl, selected.service_owned):
            raise ValueError("Broad rule survived filtering")
    for names in (original_exact, original_suffix):
        if any(not match_rule(name, exact, suffix) for name in names):
            raise ValueError("Minimization lost an input condition")
    return DomainSets(exact, suffix, core_exact, core_suffix, smart_exact, smart_suffix, original_exact, original_suffix, popular, before_minimize, count)
