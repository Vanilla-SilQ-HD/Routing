"""Domain normalization, public-suffix handling and rule minimization.

Pure functions with no network or filesystem access, shared by the build and by
any external consumer that needs to reason about routing rules.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from typing import Any, cast

import idna

from .errors import RoutingError

ASCII_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def normalize_domain(value: Any) -> str:
    """Canonical IDNA name; never turn a URL, IP or wildcard into a domain."""
    if not isinstance(value, str):
        raise ValueError("domain is not a string")
    value = value.strip().lower()
    if value.endswith("."):
        value = value[:-1]
    if not value or any(c in value for c in "/:@*\\?#"):
        raise ValueError("not a plain domain name")
    if re.fullmatch(r"[0-9.]+", value):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            raise ValueError("IP addresses are not domain rules")
    if not value.isascii() or any(label.startswith("xn--") for label in value.split(".")):
        try:
            value = idna.encode(value, uts46=True, transitional=False, std3_rules=True).decode("ascii")
        except idna.IDNAError as exc:
            raise ValueError("invalid IDNA name") from exc
    if len(value) > 253 or any(not ASCII_LABEL.fullmatch(label) for label in value.split(".")):
        raise ValueError("invalid DNS labels")
    return cast(str, value)


class PublicSuffixes:
    def __init__(self, text: str) -> None:
        self.exact: set[str] = set()
        self.wildcard: set[str] = set()
        self.exceptions: set[str] = set()
        self.private_wildcard = set()
        private = False
        for line in text.splitlines():
            line = line.strip()
            if line == "// ===BEGIN PRIVATE DOMAINS===":
                private = True
            if not line or line.startswith("//"):
                continue
            target = self.exact
            if line.startswith("!:"):
                raise RoutingError("Malformed PSL exception")
            if line.startswith("!"):
                target, line = self.exceptions, line[1:]
            elif line.startswith("*."):
                target, line = self.wildcard, line[2:]
            normalized = normalize_domain(line)
            target.add(normalized)
            if private and target is self.wildcard:
                self.private_wildcard.add(normalized)

    @property
    def count(self) -> int:
        return len(self.exact) + len(self.wildcard) + len(self.exceptions)

    def is_public_suffix(self, name: str) -> bool:
        if name in self.exceptions:
            return False
        if "." not in name or name in self.exact:
            return True
        return name.partition(".")[2] in self.wildcard

    def is_broad_routing_suffix(self, name: str) -> bool:
        # PRIVATE wildcard entries often isolate individual tenants' cookies.
        # e.g. *.eth.limo does NOT mean blocked-tenant.eth.limo covers all eth.limo.
        if name in self.private_wildcard:
            return True
        if name.partition(".")[2] in self.private_wildcard and name not in self.exact:
            return False
        return self.is_public_suffix(name)

    def registrable_domain(self, name: str) -> str:
        """Return the registrable domain (public suffix plus one label) for a host.

        Falls back to the name itself when no parent is a known public suffix, so
        already-registrable input is returned unchanged."""
        for parent in parents(name):
            if self.is_public_suffix(parent):
                index = name[: len(name) - len(parent) - 1]
                # One label before the public suffix.
                return index.split(".")[-1] + "." + parent
        return name


def parents(name: str) -> Iterator[str]:
    offset = name.find(".")
    while offset >= 0:
        yield name[offset + 1:]
        offset = name.find(".", offset + 1)


def exclusion_reason(kind: str, name: str, shared: dict[str, str], psl: PublicSuffixes, service_owned: Any = ()) -> str | None:
    if name in shared:
        return "shared-infrastructure: " + shared[name]
    if kind == "domain_suffix" and psl.is_broad_routing_suffix(name):
        if name in service_owned or any(parent in service_owned for parent in parents(name)):
            return None
        if "." not in name and name not in psl.exact:
            return "single-label: имя без доменной зоны"
        return "public-suffix: целая зона или общая платформа (PSL ICANN/PRIVATE)"
    return None


def match_rule(name: str, exact: Any, suffix: Any) -> tuple[str, str] | None:
    if name in exact:
        return "domain", name
    if name in suffix:
        return "domain_suffix", name
    for parent in parents(name):
        if parent in suffix:
            return "domain_suffix", parent
    return None


def minimize(exact: dict[str, int], suffix: dict[str, int]) -> tuple[dict[str, int], dict[str, int]]:
    """Remove only rules covered by an existing suffix, without creating any new suffix."""
    minimal_suffix = {name: mask for name, mask in suffix.items() if not any(parent in suffix for parent in parents(name))}
    minimal_exact = {name: mask for name, mask in exact.items() if not match_rule(name, {}, suffix)}
    return minimal_exact, minimal_suffix
