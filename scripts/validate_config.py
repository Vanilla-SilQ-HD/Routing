"""Validate every tracked configuration file against its local JSON Schema."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {
    "sources.json": "sources_schema.json",
    "service-networks.json": "service_networks_schema.json",
    "registry-ip-sources.json": "registry_ip_sources_schema.json",
    "manual-vpn.json": "manual_vpn_schema.json",
    "direct-exceptions.json": "direct_exceptions_schema.json",
    "policy.json": "policy_schema.json",
    "probes.json": "probes_schema.json",
    "monitoring.json": "monitoring_schema.json",
    "tools-lock.json": "tools_lock_schema.json",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def validate_semantics(configs: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for name in ("sources.json", "service-networks.json", "registry-ip-sources.json"):
        ids = [source["id"] for source in configs[name]["sources"]]
        if len(ids) != len(set(ids)):
            errors.append(f"{name}: duplicate source id")
    source_ids = {source["id"] for source in configs["sources.json"]["sources"]}
    missing = set(configs["sources.json"].get("core_excluded_sources", [])) - source_ids
    if missing:
        errors.append(f"sources.json: unknown core_excluded_sources: {sorted(missing)}")
    probes = configs["probes.json"]
    unknown_probes = set(probes["expectations"]) - set(probes["domains"])
    if unknown_probes:
        errors.append(f"probes.json: expectations missing from domains: {sorted(unknown_probes)}")
    return errors


def validate_all(root: Path) -> list[str]:
    errors: list[str] = []
    configs: dict[str, Any] = {}
    for config_name, schema_name in SCHEMAS.items():
        config_path = root / "config" / config_name
        schema_path = root / "schemas" / schema_name
        try:
            config = load_json(config_path)
            schema = load_json(schema_path)
            validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
            for error in sorted(validator.iter_errors(config), key=lambda item: list(item.absolute_path)):
                location = ".".join(str(part) for part in error.absolute_path) or "<root>"
                errors.append(f"{config_name}:{location}: {error.message}")
            configs[config_name] = config
        except (OSError, ValueError, jsonschema.SchemaError) as exc:
            errors.append(f"{config_name}: {exc}")
    if len(configs) == len(SCHEMAS):
        errors.extend(validate_semantics(configs))
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    errors = validate_all(args.root.resolve())
    if errors:
        for error in errors:
            print(f"CONFIG ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Validated {len(SCHEMAS)} configuration files against local schemas")


if __name__ == "__main__":
    main()
