"""Build small JSON shards for browser-side domain lookup."""

from __future__ import annotations

import json
import string
from pathlib import Path
from typing import Any

SHARD_KEYS = (*tuple(string.ascii_lowercase + string.digits), "_")


def shard_key(domain: str) -> str:
    """Return the shard key for a normalized domain condition."""
    first = domain[:1].lower()
    return first if first and first in string.ascii_lowercase + string.digits else "_"


def _rules(payload: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {"domain": [], "domain_suffix": []}
    for rule in payload.get("rules", []):
        if not isinstance(rule, dict):
            continue
        for kind in result:
            values = rule.get(kind, [])
            if isinstance(values, list):
                result[kind].extend(str(value) for value in values)
    return {kind: sorted(set(values)) for kind, values in result.items()}


def write_domain_shards(source: Path, destination: Path) -> dict[str, Any]:
    """Write one compact shard per first character and return its index."""
    payload = json.loads(source.read_text(encoding="utf-8"))
    rules = _rules(payload)
    grouped: dict[str, dict[str, list[str]]] = {}
    for kind, values in rules.items():
        for value in values:
            grouped.setdefault(shard_key(value), {"domain": [], "domain_suffix": []})[kind].append(value)

    destination.mkdir(parents=True, exist_ok=True)
    shards: dict[str, dict[str, int]] = {}
    for key in sorted(grouped):
        shard = grouped[key]
        target = destination / f"{key}.json"
        target.write_text(
            json.dumps(
                {"version": payload.get("version", 1), "rules": [shard]},
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        shards[key] = {kind: len(values) for kind, values in shard.items()}

    index = {
        "version": payload.get("version", 1),
        "source": "blocked-domains.json",
        "shards": shards,
        "total": {kind: len(values) for kind, values in rules.items()},
    }
    (destination / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return index
