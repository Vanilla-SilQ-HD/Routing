"""Public Python API for the Routing rule-set builder.

The heavy implementation modules are loaded lazily on first attribute access so
that lightweight submodules (e.g. routing.datasets) can be imported from the
build scripts without triggering a circular import.
"""
from __future__ import annotations

from typing import Any

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


def __getattr__(name: str) -> Any:
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from . import api
    return getattr(api, name)
