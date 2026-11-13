"""Compute the configuration recipe hash shared by the build and the publisher."""
from __future__ import annotations

from pathlib import Path

from .util import file_sha256


def recipe_hashes(root: str | Path) -> dict[str, str]:
    """Hash every file that influences the produced rule sets.

    The build writes this into manifest.configuration_sha256, and the publisher
    recomputes it to prove the artifact came from the same checkout."""
    root = Path(root)
    paths = list((root / "config").glob("*.json")) + list((root / "scripts").glob("*.py"))
    paths += list((root / "schemas").glob("*.json")) + list((root / "routing").glob("*.py"))
    paths += [root / "requirements.txt", root / "requirements-dev.txt",
              root / "pyproject.toml", root / ".github/workflows/build.yml"]
    return {p.relative_to(root).as_posix(): file_sha256(p) for p in sorted(paths) if p.is_file()}
