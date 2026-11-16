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
    preset_tag: str | None = None  # rule-set tag used by the AWG Manager presets


DATASETS: tuple[Dataset, ...] = (
    Dataset("blocked-domains", "Домены · Full", "Полная база для маршрутизации и DNS", "domain", None, "routing"),
    Dataset("blocked-domains-core", "Домены · Compact", "Компактная база для слабых устройств", "domain", "core", "routing-core"),
    Dataset("blocked-domains-smart", "Домены · Smart", "Compact + популярные домены из Full (Tranco)", "domain", "smart", "routing-smart"),
    Dataset("blocked-services-ip", "Сети приложений", "Проверенные сети Telegram", "cidr", "service_networks", "routing-services"),
    Dataset("blocked-registry-ip", "Точные IP", "Только /32 и /128 из блок-листов", "cidr", "registry_ip", "routing-registry-ip"),
    Dataset("blocked-registry-ip-cidr", "Широкие CIDR", "Необязательное дополнение с предупреждением", "cidr", "registry_cidr", "routing-registry-ip-cidr"),
    Dataset("routing-direct-exceptions", "Direct-исключения", "Приоритетные правила Direct", "domain", "direct_exceptions"),
)

DATASET_NAMES: tuple[str, ...] = tuple(d.name for d in DATASETS)


@dataclass(frozen=True)
class Preset:
    identifier: str    # preset id consumed by AWG Manager
    title: str         # display name
    tags: tuple[str, ...]  # rule-set tags, in evaluation order
    notice: str        # user-facing caveat

    def rule_sets(self, release_base: str) -> list[dict[str, str]]:
        return [{"tag": tag, "url": release_base + PRESET_FILES[tag]} for tag in self.tags]


PRESET_FILES: dict[str, str] = {
    dataset.preset_tag: dataset.name + ".srs" for dataset in DATASETS if dataset.preset_tag
}

PRESETS: tuple[Preset, ...] = (
    Preset("routing-full", "Routing · Full", ("routing", "routing-services", "routing-registry-ip"),
           "Полная доменная база и точные IP. Direct-исключения настройте отдельным приоритетным правилом."),
    Preset("routing-compact", "Routing · Compact", ("routing-core", "routing-services", "routing-registry-ip"),
           "Компактная доменная база без двух крупнейших реестров, сервисные сети и точные IP. "
           "Direct-исключения настраиваются отдельно."),
    Preset("routing-smart", "Routing · Smart", ("routing-smart", "routing-services", "routing-registry-ip"),
           "Compact плюс популярные домены из полного набора (Tranco top-1M): баланс покрытия и размера. "
           "Direct-исключения настраиваются отдельно."),
    Preset("routing-wide-cidr", "Routing · Wide CIDR", ("routing-registry-ip-cidr",),
           "Дополнительные широкие CIDR. Подключайте только после проверки покрытия."),
)


def dataset_sizes(manifest: dict[str, Any]) -> dict[str, int]:
    """Map each dataset name to its compiled SRS size from a build manifest."""
    sizes: dict[str, int] = {}
    for dataset in DATASETS:
        if dataset.manifest_key is None:
            sizes[dataset.name] = manifest["output"]["srs_bytes"]
        else:
            sizes[dataset.name] = manifest[dataset.manifest_key]["output"]["srs_bytes"]
    return sizes
