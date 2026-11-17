"""Typed source attribution sets used by the routing build."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SourceSet:
    """Immutable set of source indexes attributed by a compact bit mask.

    Stages only add sources, combine sets and ask for names, so attribution
    stays independent of how sources happen to be indexed.
    """

    mask: int = 0

    @classmethod
    def from_mask(cls, mask: int) -> SourceSet:
        return cls(mask)

    def add(self, index: int) -> SourceSet:
        if index < 0:
            raise IndexError(f"source index out of range: {index}")
        return SourceSet(self.mask | (1 << index))

    def __or__(self, other: SourceSet) -> SourceSet:
        return SourceSet(self.mask | other.mask)

    def __and__(self, other: SourceSet) -> SourceSet:
        return SourceSet(self.mask & other.mask)

    def __contains__(self, index: object) -> bool:
        return isinstance(index, int) and index >= 0 and bool(self.mask & (1 << index))

    def names(self, sources: Sequence[dict[str, Any]]) -> list[str]:
        return [source["id"] for index, source in enumerate(sources) if index in self]

    def __bool__(self) -> bool:
        return bool(self.mask)
