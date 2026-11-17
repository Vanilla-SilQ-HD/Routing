"""Render the output-format reference in docs/DATA_FORMATS.md from the JSON Schemas.

The schemas in schemas/output describe every published artifact and carry the
human-readable ``description`` of each field. This script turns them into a
Markdown field table between the generated markers, so the documentation cannot
drift away from the validated format. ``--check`` fails when the block is stale.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas" / "output"
DOC_PATH = ROOT / "docs" / "DATA_FORMATS.md"
BEGIN = "<!-- BEGIN GENERATED:schemas -->"
END = "<!-- END GENERATED:schemas -->"

ARTIFACTS: tuple[tuple[str, str], ...] = (
    ("manifest_schema.json", "manifest.json"),
    ("catalog_schema.json", "catalog.json"),
    ("presets_schema.json", "presets.user.json"),
    ("monitoring_schema.json", "monitoring.json"),
)


def type_label(node: dict[str, Any]) -> str:
    """Short human-readable type of a schema node."""
    if "const" in node:
        return f"const `{json.dumps(node['const'], ensure_ascii=False)}`"
    if "enum" in node:
        return "enum " + " / ".join(f"`{value}`" for value in node["enum"])
    kind = node.get("type")
    if isinstance(kind, list):
        return " / ".join(kind)
    if kind == "array":
        items = node.get("items")
        inner = type_label(items) if isinstance(items, dict) else "any"
        return f"array<{inner}>"
    if kind == "object" and isinstance(node.get("additionalProperties"), dict):
        inner = type_label(node["additionalProperties"])
        return f"object<string, {inner}>"
    if isinstance(kind, str):
        return kind
    return "any"


def cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def walk(node: dict[str, Any], prefix: str, rows: list[tuple[str, str, str]]) -> None:
    for name, child in (node.get("properties") or {}).items():
        if not isinstance(child, dict):
            continue
        path = f"{prefix}.{name}" if prefix else name
        rows.append((path, type_label(child), str(child.get("description", ""))))
        walk(child, path, rows)
        items = child.get("items")
        if isinstance(items, dict):
            walk(items, f"{path}[]", rows)
        extra = child.get("additionalProperties")
        if isinstance(extra, dict):
            rows.append((f"{path}.<key>", type_label(extra), str(extra.get("description", ""))))


def render_block() -> str:
    blocks = [BEGIN, ""]
    for schema_name, artifact in ARTIFACTS:
        schema = json.loads((SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
        rows: list[tuple[str, str, str]] = []
        walk(schema, "", rows)
        blocks.append(f"### `{artifact}`")
        blocks.append("")
        if schema.get("description"):
            blocks.append(str(schema["description"]))
            blocks.append("")
        blocks.append("| Поле | Тип | Описание |")
        blocks.append("| --- | --- | --- |")
        for path, kind, description in rows:
            blocks.append(f"| `{cell(path)}` | {cell(kind)} | {cell(description) or '—'} |")
        blocks.append("")
    blocks.append(END)
    return "\n".join(blocks)


def replace_block(document: str, block: str) -> str:
    start = document.find(BEGIN)
    stop = document.find(END)
    if start < 0 or stop < 0:
        raise ValueError(f"{DOC_PATH} is missing the generated markers {BEGIN} / {END}")
    return document[:start] + block + document[stop + len(END) :]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Exit 1 when the generated block is stale")
    args = parser.parse_args()
    block = render_block()
    document = DOC_PATH.read_text(encoding="utf-8")
    try:
        updated = replace_block(document, block)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1) from exc
    if args.check:
        if updated != document:
            print("docs/DATA_FORMATS.md is stale: run python scripts/gen_docs.py", file=sys.stderr)
            raise SystemExit(1)
        print("docs/DATA_FORMATS.md is up to date")
        return
    if updated != document:
        DOC_PATH.write_text(updated, encoding="utf-8", newline="\n")
        print("Updated docs/DATA_FORMATS.md")
    else:
        print("docs/DATA_FORMATS.md is up to date")


if __name__ == "__main__":
    main()
