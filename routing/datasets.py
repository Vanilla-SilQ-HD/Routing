"""Single registry of the rule-set datasets produced by the build.

Every consumer (build catalog, release publisher, AWG output validator, HTML
report, Pages step) reads the inventory from here instead of keeping its own copy.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Dataset:
    name: str          # file stem, e.g. "blocked-domains-core"
    title: str         # human title used in the report and release body
    description: str   # short purpose
    kind: str          # "domain" | "cidr"
    manifest_key: str | None  # manifest section carrying srs_bytes for this set


DATASETS: tuple[Dataset, ...] = (
    Dataset("blocked-domains", "Домены · Full", "Полная база для маршрутизации и DNS", "domain", None),
    Dataset("blocked-domains-core", "Домены · Compact", "Компактная база для слабых устройств", "domain", "core"),
    Dataset("blocked-domains-smart", "Домены · Smart", "Compact + популярные домены из Full (Tranco)", "domain", "smart"),
    Dataset("blocked-services-ip", "Сети приложений", "Проверенные сети Telegram", "cidr", "service_networks"),
    Dataset("blocked-registry-ip", "Точные IP", "Только /32 и /128 из блок-листов", "cidr", "registry_ip"),
    Dataset("blocked-registry-ip-cidr", "Широкие CIDR", "Необязательное дополнение с предупреждением", "cidr", "registry_cidr"),
    Dataset("routing-direct-exceptions", "Direct-исключения", "Приоритетные правила Direct", "domain", "direct_exceptions"),
)

DATASET_NAMES: tuple[str, ...] = tuple(d.name for d in DATASETS)


def dataset_sizes(manifest: dict[str, Any]) -> dict[str, int]:
    """Map each dataset name to its compiled SRS size from a build manifest."""
    sizes: dict[str, int] = {}
    for dataset in DATASETS:
        if dataset.manifest_key is None:
            sizes[dataset.name] = manifest["output"]["srs_bytes"]
        else:
            sizes[dataset.name] = manifest[dataset.manifest_key]["output"]["srs_bytes"]
    return sizes
