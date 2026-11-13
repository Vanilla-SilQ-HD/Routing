"""Validate generated build artifacts against the output JSON Schemas.

These schemas double as the published format documentation for external consumers.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = {
    "manifest.json": "manifest_schema.json",
    "catalog.json": "catalog_schema.json",
    "presets.user.json": "presets_schema.json",
    "monitoring.json": "monitoring_schema.json",
}


def validate_outputs(build_dir: Path, schema_dir: Path) -> list[str]:
    errors: list[str] = []
    for artifact, schema_name in ARTIFACTS.items():
        path = build_dir / artifact
        if not path.is_file():
            continue  # monitoring.json is optional (produced by the monitor job)
        try:
            data: Any = json.loads(path.read_text(encoding="utf-8"))
            schema = json.loads((schema_dir / schema_name).read_text(encoding="utf-8"))
            validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
            for error in sorted(validator.iter_errors(data), key=lambda item: list(item.absolute_path)):
                location = ".".join(str(part) for part in error.absolute_path) or "<root>"
                errors.append(f"{artifact}:{location}: {error.message}")
        except (OSError, ValueError, jsonschema.SchemaError) as exc:
            errors.append(f"{artifact}: {exc}")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", type=Path)
    parser.add_argument("--schema-dir", type=Path, default=ROOT / "schemas" / "output")
    args = parser.parse_args()
    errors = validate_outputs(args.build_dir, args.schema_dir)
    if errors:
        for error in errors:
            print(f"OUTPUT ERROR: {error}")
        raise SystemExit(1)
    print(f"Validated build artifacts in {args.build_dir} against output schemas")


if __name__ == "__main__":
    main()
