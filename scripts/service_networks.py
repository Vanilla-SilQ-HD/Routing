"""Strict service-owned CIDR inputs.

Re-exported from routing.networks so existing imports and the public API keep working.
"""
from routing.networks import *  # noqa: F403
from routing.networks import ServiceNetworkError, normalize_networks

__all__ = ["ServiceNetworkError", "normalize_networks"]
