from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a target is outside the authorized engagement scope."""


@dataclass(frozen=True)
class Target:
    url: str

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""


def _matches_pattern(target: Target, pattern: str) -> bool:
    if "://" in pattern:
        return fnmatch(target.url, pattern)
    return fnmatch(target.host, pattern)


def enforce_scope(target: Target, scope: list[str], out_of_scope: list[str]) -> None:
    if any(_matches_pattern(target, pattern) for pattern in out_of_scope):
        raise ScopeError(f"Target is explicitly out of scope: {target.url}")

    if scope and not any(_matches_pattern(target, pattern) for pattern in scope):
        raise ScopeError(f"Target is not in scope: {target.url}")
