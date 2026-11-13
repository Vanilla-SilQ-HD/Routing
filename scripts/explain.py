"""Explain why a domain is routed to VPN or Direct using a published build.

Reads the manifest and the per-set JSON files produced by the build (locally or
from a release directory) and reports the matched rule, its sources and any
Direct exception. No network access is required for a local build directory.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if str(Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routing.domains import match_rule, normalize_domain


def load_rules(path: Path) -> dict[str, set[str]]:
    """Load domain and domain_suffix groups from a build JSON rule-set."""
    groups: dict[str, set[str]] = {"domain": set(), "domain_suffix": set()}
    if not path.is_file():
        return groups
    data = json.loads(path.read_text(encoding="utf-8"))
    for rule in data.get("rules", []):
        for kind in groups:
            values = rule.get(kind, [])
            if isinstance(values, list):
                groups[kind].update(values)
    return groups


def explain(build_dir: Path, domain: str) -> dict[str, Any]:
    name = normalize_domain(domain)
    manifest = json.loads((build_dir / "manifest.json").read_text(encoding="utf-8"))
    full = load_rules(build_dir / "blocked-domains.json")
    direct = load_rules(build_dir / "routing-direct-exceptions.json")
    direct_match = match_rule(name, direct["domain"], direct["domain_suffix"])
    match = match_rule(name, full["domain"], full["domain_suffix"])
    decision = "Direct" if direct_match else ("VPN" if match else "Direct")
    result: dict[str, Any] = {"domain": name, "decision": decision}
    if direct_match:
        result["reason"] = "direct-exception"
        result["matched_rule"] = direct_match[1]
        exceptions = manifest.get("direct_exceptions", {}).get("rules", [])
        for rule in exceptions:
            if rule.get("domain") == direct_match[1]:
                result["exception"] = {"reason": rule.get("reason"), "review_after": rule.get("review_after")}
    elif match:
        result["matched_rule"] = match[1]
        result["matched_type"] = match[0]
        # Find which sources mention this rule via the manifest intersections.
        for probe_source in manifest.get("sources", []):
            if probe_source.get("id") == match[1]:
                result["sources"] = [match[1]]
    else:
        result["reason"] = "no-rule-matches; default route is Direct"
    # Report Compact/Smart coverage for the same domain.
    for label, filename in (("compact", "blocked-domains-core.json"), ("smart", "blocked-domains-smart.json")):
        rules = load_rules(build_dir / filename)
        covered = match_rule(name, rules["domain"], rules["domain_suffix"]) is not None
        result[label] = "VPN" if covered else "not-covered"
    result["built_at"] = manifest.get("built_at")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", help="Domain to explain, e.g. example.com")
    parser.add_argument("--build-dir", type=Path, default=Path("dist"),
                        help="Directory with manifest.json and the per-set JSON files")
    parser.add_argument("--json", action="store_true", help="Print the raw JSON result")
    args = parser.parse_args()
    try:
        result = explain(args.build_dir, args.domain)
    except FileNotFoundError as exc:
        print(f"Build artifact not found: {exc}. Point --build-dir at a build output.", file=sys.stderr)
        raise SystemExit(1)
    except ValueError as exc:
        print(f"Invalid domain: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    print(f"Домен: {result['domain']}")
    print(f"Решение: {result['decision']}")
    if result.get("matched_rule"):
        print(f"Сработавшее правило: {result['matched_rule']} ({result.get('matched_type', 'direct-exception')})")
    if result.get("exception"):
        print(f"Direct-исключение: {result['exception']['reason']} (пересмотр {result['exception']['review_after']})")
    if result.get("reason"):
        print(f"Причина: {result['reason']}")
    print(f"Compact: {result['compact']} · Smart: {result['smart']}")
    print(f"Сборка: {result['built_at']}")


if __name__ == "__main__":
    main()
