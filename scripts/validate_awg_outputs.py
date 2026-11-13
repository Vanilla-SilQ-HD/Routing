"""Validate generated AWG Manager catalog and user presets offline."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if str(Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routing.datasets import DATASET_NAMES

EXPECTED_DATASETS = set(DATASET_NAMES)
EXPECTED_PRESETS = {
    "routing-full": {"routing", "routing-services", "routing-registry-ip"},
    "routing-compact": {"routing-core", "routing-services", "routing-registry-ip"},
    "routing-smart": {"routing-smart", "routing-services", "routing-registry-ip"},
    "routing-wide-cidr": {"routing-registry-ip-cidr"},
}


class AWGOutputError(ValueError):
    pass


def validate_outputs(build_dir: Path) -> dict[str, Any]:
    catalog = json.loads((build_dir / "catalog.json").read_text(encoding="utf-8"))
    sources = catalog.get("sources")
    if not isinstance(sources, list) or len(sources) != 1:
        raise AWGOutputError("Catalog must contain exactly one routing source")
    source = sources[0]
    if source.get("id") != "routing" or set(source.get("names", [])) != EXPECTED_DATASETS:
        raise AWGOutputError("Catalog dataset inventory is incomplete")
    if not source.get("url", "").startswith("https://") or "{}" not in source["url"]:
        raise AWGOutputError("Catalog URL must be an HTTPS template")

    presets_document = json.loads((build_dir / "presets.user.json").read_text(encoding="utf-8"))
    presets = presets_document.get("presets")
    if not isinstance(presets, list) or {item.get("id") for item in presets} != set(EXPECTED_PRESETS):
        raise AWGOutputError("Preset inventory is incomplete")
    for preset in presets:
        engine = preset.get("engines", {}).get("singbox", {})
        rule_sets = engine.get("ruleSets", [])
        if engine.get("action") != "tunnel":
            raise AWGOutputError(f"Preset {preset['id']} must use the tunnel action")
        if {item.get("tag") for item in rule_sets} != EXPECTED_PRESETS[preset["id"]]:
            raise AWGOutputError(f"Preset {preset['id']} has an unexpected rule-set composition")
        if any(item.get("tag") == "routing-direct-exceptions" for item in rule_sets):
            raise AWGOutputError("Direct exceptions must not be routed to VPN")
        for item in rule_sets:
            if not item.get("url", "").startswith("https://") or not item["url"].endswith(".srs"):
                raise AWGOutputError(f"Preset {preset['id']} contains an invalid SRS URL")
    return {"catalog_datasets": len(EXPECTED_DATASETS), "presets": len(presets)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(validate_outputs(args.build_dir)))
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"AWG OUTPUT INVALID: {exc}\n")


if __name__ == "__main__":
    main()
