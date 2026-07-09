"""Target definition and scope enforcement.

StelarStrike refuses to actively test anything that isn't explicitly
listed in the engagement scope. This is intentional friction: scope
mistakes are how authorized tests turn into unauthorized access.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class Target:
    url: str

    @property
    def host(self) -> str:
        return urlparse(self.url).netloc


class ScopeError(Exception):
    """Raised when a target does not match the engagement scope."""


def _matches_any(host_or_url: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(host_or_url, pattern) for pattern in patterns)


def enforce_scope(target: Target, scope: list[str], out_of_scope: list[str]) -> None:
    """Raise ScopeError unless the target is explicitly in scope and not excluded."""
    if _matches_any(target.url, out_of_scope) or _matches_any(target.host, out_of_scope):
        raise ScopeError(f"'{target.url}' matches an out-of-scope pattern. Refusing to test.")

    if scope and not (_matches_any(target.url, scope) or _matches_any(target.host, scope)):
        raise ScopeError(
            f"'{target.url}' is not listed in engagement.scope. "
            f"Add it to config.yaml before scanning it."
        )
