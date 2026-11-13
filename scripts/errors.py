"""Shared exception hierarchy for Routing tools.

Re-exported from the routing package so there is a single RoutingError type.
"""
from routing.errors import RoutingError

__all__ = ["RoutingError"]
