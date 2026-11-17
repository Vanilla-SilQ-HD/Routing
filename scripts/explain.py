"""Compatibility shim for legacy import path.

Provides `explain` function and console entrypoint expected by existing
tests and external scripts that import from the `scripts` directory.
"""

import sys
from pathlib import Path

if str(Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routing.explain import explain, main

__all__ = ["explain", "main"]

if __name__ == "__main__":
    main()
