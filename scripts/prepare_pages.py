#!/usr/bin/env python
"""Prepare the GitHub Pages artifact from a completed build.

Usage:
    python scripts/prepare_pages.py <build_dir> <output_dir>

This replaces the manual cp steps in the Pages workflow and ensures
the published site always matches the datasets registry.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

if str(Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routing.datasets import DATASETS
from routing.domain_shards import write_domain_shards

CORE_FILES = (
    "status.json",
    "updated.json",
    "manifest.json",
    "domain-changes.json",
    "catalog.json",
    "presets.user.json",
)

HUMAN_READABLE = ("blocked-domains.txt", "blocked-domains-core.txt")

UNAVAILABLE_MONITORING: dict[str, object] = {
    "schema_version": 1,
    "generated_at": None,
    "provider": "Globalping",
    "vpn_measurement": "not_performed",
    "automatic_route_changes": False,
    "history": [],
    "unavailable": True,
}

UNAVAILABLE_HTML = (
    '<!doctype html><html lang="ru"><meta charset="utf-8">'
    "<title>Routing · Мониторинг</title>"
    '<body style="background:#08111f;color:#e7f0fc;font:16px system-ui;'
    'max-width:800px;margin:60px auto;padding:0 20px">'
    "<h1>Мониторинг временно недоступен</h1>"
    "<p>Внешняя проверка не выполнилась в этом запуске. "
    "Маршруты и наборы правил опубликованы штатно.</p>"
    '<p><a style="color:#70b7ff" href="index.html">Routing Dashboard</a></p>'
    "</body></html>"
)


def _publish_monitoring(build_dir: Path, output_dir: Path) -> None:
    """Publish the monitoring page, or a placeholder when the check did not run."""
    if (build_dir / "monitoring.json").is_file():
        shutil.copy2(build_dir / "monitoring.json", output_dir / "monitoring.json")
        shutil.copy2(build_dir / "monitoring.html", output_dir / "monitoring.html")
        stale = build_dir / "stale-candidates.json"
        if stale.is_file():
            shutil.copy2(stale, output_dir / "stale-candidates.json")
        return
    (output_dir / "monitoring.json").write_text(json.dumps(UNAVAILABLE_MONITORING, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "monitoring.html").write_text(UNAVAILABLE_HTML, encoding="utf-8")


def prepare_pages(build_dir: Path, output_dir: Path) -> None:
    """Copy build artifacts to the Pages output directory.

    Always publishes:
      - report.html as index.html
      - status.json, updated.json, manifest.json
      - domain-changes.json, catalog.json, presets.user.json
      - All .srs files listed in routing.datasets.DATASETS
      - blocked-domains.txt and blocked-domains-core.txt (human-readable)
      - monitoring.json and monitoring.html (placeholder if unavailable)
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(build_dir / "report.html", output_dir / "index.html")
    for name in CORE_FILES:
        shutil.copy2(build_dir / name, output_dir / name)

    for dataset in DATASETS:
        src = build_dir / f"{dataset.name}.srs"
        if not src.is_file():
            raise FileNotFoundError(f"Missing required artifact: {src}")
        shutil.copy2(src, output_dir / f"{dataset.name}.srs")

    for name in HUMAN_READABLE:
        src = build_dir / name
        if src.is_file():
            shutil.copy2(src, output_dir / name)

    # Full rules are too large for the dashboard payload. Publish small, cacheable
    # shards so a lookup downloads only the relevant prefix.
    write_domain_shards(build_dir / "blocked-domains.json", output_dir / "domains")
    _publish_monitoring(build_dir, output_dir)


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <build_dir> <output_dir>", file=sys.stderr)
        sys.exit(1)
    build_dir = Path(sys.argv[1]).resolve()
    output_dir = Path(sys.argv[2]).resolve()
    if not build_dir.is_dir():
        print(f"Build directory does not exist: {build_dir}", file=sys.stderr)
        sys.exit(1)
    prepare_pages(build_dir, output_dir)
    print(f"Pages artifact prepared in {output_dir}")


if __name__ == "__main__":
    main()
