"""
Base class every vulnerability plugin extends.

Design goal: adding vuln class #9 in v1.1 should mean "create one new
file that subclasses VulnerabilityPlugin, register it" — nothing else
in the orchestrator should need to change.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx

from stelarstrike.core.report import Finding
from stelarstrike.core.target import Target


@dataclass
class PluginContext:
    target: Target
    http_client: httpx.AsyncClient
    options: dict[str, Any]
    allow_active_payloads: bool
    semaphore: asyncio.Semaphore


class VulnerabilityPlugin(ABC):
    """Subclass this and set `id` + `name` to add a new vulnerability check."""

    id: str = "base"
    name: str = "Base Plugin"
    default_severity: str = "medium"

    def __init__(self, ctx: PluginContext):
        self.ctx = ctx

    @property
    def target_url(self) -> str:
        return self.ctx.target.url

    @property
    def options(self) -> dict[str, Any]:
        return self.ctx.options

    async def get(self, url: str, **kwargs) -> httpx.Response:
        async with self.ctx.semaphore:
            return await self.ctx.http_client.get(url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        async with self.ctx.semaphore:
            return await self.ctx.http_client.post(url, **kwargs)

    def finding(
        self,
        title: str,
        url: str,
        severity: str | None = None,
        parameter: str | None = None,
        evidence: str | None = None,
        description: str = "",
        remediation: str = "",
        confidence: str = "medium",
        cwe: str | None = None,
    ) -> Finding:
        return Finding(
            plugin=self.id,
            title=title,
            severity=severity or self.default_severity,
            url=url,
            parameter=parameter,
            evidence=evidence,
            description=description,
            remediation=remediation,
            confidence=confidence,
            cwe=cwe,
        )

    @abstractmethod
    async def run(self) -> list[Finding]:
        """Execute the check and return any findings. Must not raise on normal errors."""
        raise NotImplementedError
