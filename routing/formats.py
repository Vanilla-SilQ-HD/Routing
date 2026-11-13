"""Text exporters for other clients, generated from the same build data.

These are derived views, not separate data sources: the canonical SRS sets stay
the source of truth, and each exporter reads the per-set JSON rules.
"""
from __future__ import annotations

from typing import Any


def _groups(rules: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    domains = sorted(rules.get("domain", []))
    suffixes = sorted(rules.get("domain_suffix", []))
    cidrs = sorted(rules.get("ip_cidr", []))
    return domains, suffixes, cidrs


def dnsmasq_nfset(rules: dict[str, Any], set_name: str = "vpn") -> str:
    """dnsmasq + nftables: route matched domains into an nft set."""
    domains, suffixes, _ = _groups(rules)
    lines = [f"nftset=/{name}/{set_name}" for name in domains]
    lines += [f"nftset=/*.{name}/{set_name}" for name in suffixes]
    return "\n".join(lines) + ("\n" if lines else "")


def ipset_domains(rules: dict[str, Any]) -> str:
    """Plain domain list for ipset/nftset population scripts."""
    domains, suffixes, _ = _groups(rules)
    return "\n".join(domains + suffixes) + "\n"


def adguard_upstream(rules: dict[str, Any], upstream: str) -> str:
    """AdGuard Home / Pi-hole style per-domain upstream rules."""
    domains, suffixes, _ = _groups(rules)
    lines = [f"[/{name}/]{upstream}" for name in domains]
    lines += [f"[/.{name}/]{upstream}" for name in suffixes]
    return "\n".join(lines) + ("\n" if lines else "")


def mihomo_yaml(rules: dict[str, Any], behavior: str) -> str:
    """Clash Meta / mihomo text ruleset: a YAML list of payload entries."""
    domains, suffixes, cidrs = _groups(rules)
    if behavior == "domain":
        entries = [f"  - '{name}'" for name in domains]
        entries += [f"  - '+.{name}'" for name in suffixes]
    elif behavior == "ipcidr":
        entries = [f"  - '{name}'" for name in cidrs]
    else:
        raise ValueError(f"Unsupported mihomo behavior: {behavior}")
    header = f"# mihomo ruleset, behavior={behavior}\npayload:\n"
    return header + "\n".join(entries) + ("\n" if entries else "")
