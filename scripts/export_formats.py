"""Export the build rule sets to text formats for other clients.

Reads the per-set JSON files produced by the build and writes dnsmasq, ipset,
AdGuard Home and mihomo views into an output directory. These are derived
exports; the canonical SRS sets remain the source of truth.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from routing.formats import adguard_upstream, dnsmasq_nfset, ipset_domains, mihomo_yaml


def load_rules(path: Path) -> dict[str, Any]:
    merged: dict[str, list[str]] = {"domain": [], "domain_suffix": [], "ip_cidr": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    for rule in data.get("rules", []):
        for kind in merged:
            values = rule.get(kind, [])
            if isinstance(values, list):
                merged[kind].extend(values)
    return merged


def export(build_dir: Path, output_dir: Path, adguard_dns: str) -> list[str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    domain_sets = {
        "blocked-domains": "full",
        "blocked-domains-core": "compact",
        "blocked-domains-smart": "smart",
    }
    for stem, label in domain_sets.items():
        path = build_dir / (stem + ".json")
        if not path.is_file():
            continue
        rules = load_rules(path)
        exports = {
            f"dnsmasq-{label}.conf": dnsmasq_nfset(rules),
            f"ipset-{label}.txt": ipset_domains(rules),
            f"adguard-{label}.txt": adguard_upstream(rules, adguard_dns),
            f"mihomo-{label}-domain.yaml": mihomo_yaml(rules, "domain"),
        }
        for name, content in exports.items():
            (output_dir / name).write_text(content, encoding="utf-8")
            written.append(name)
    for stem in ("blocked-registry-ip", "blocked-registry-ip-cidr", "blocked-services-ip"):
        path = build_dir / (stem + ".json")
        if not path.is_file():
            continue
        rules = load_rules(path)
        name = f"mihomo-{stem}-ipcidr.yaml"
        (output_dir / name).write_text(mihomo_yaml(rules, "ipcidr"), encoding="utf-8")
        written.append(name)
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=Path, default=Path("dist/formats"))
    parser.add_argument("--adguard-dns", default="https://dns.cloudflare.com/dns-query",
                        help="Upstream used in AdGuard per-domain rules (e.g. your DoH-in-VPN)")
    args = parser.parse_args()
    written = export(args.build_dir, args.output, args.adguard_dns)
    print(json.dumps({"exported": len(written), "output": str(args.output)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
