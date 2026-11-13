"""Shared logging configuration for command-line tools."""
from __future__ import annotations

import logging
import os


def configure_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else os.environ.get("ROUTING_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s", force=True)
