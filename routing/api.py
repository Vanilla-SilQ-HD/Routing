"""Stable public imports for the reviewed Routing implementation."""
from __future__ import annotations

import importlib
import sys
from types import ModuleType

from .domains import minimize, normalize_domain


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    try:
        module = importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name != name:
            raise
        module = importlib.import_module(f"scripts.{name}")
    return sys.modules.setdefault(name, module)


# Dependencies must be registered before their CLI importers are loaded.
for _name in ("errors", "logging_utils", "report", "service_networks"):
    _load(_name)
_build = _load("build")
_monitor = _load("monitor")
_publish_release = _load("publish_release")

BuildError = _build.BuildError
PublishError = _publish_release.PublishError
RoutingError = _load("errors").RoutingError
ServiceNetworkError = _load("service_networks").ServiceNetworkError
classify_result = _monitor.classify_result
normalize_networks = _load("service_networks").normalize_networks
parse_checksums = _publish_release.parse_checksums
releases_to_prune = _publish_release.releases_to_prune

__all__ = [
    "BuildError",
    "PublishError",
    "RoutingError",
    "ServiceNetworkError",
    "classify_result",
    "minimize",
    "normalize_domain",
    "normalize_networks",
    "parse_checksums",
    "releases_to_prune",
]
