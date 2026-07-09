from __future__ import annotations

from dataclasses import dataclass, field

from stelarstrike.core.report import Finding


@dataclass
class PluginContext:
    target_url: str
    config: dict[str, object] = field(default_factory=dict)


class VulnerabilityPlugin:
    id = "base"
    name = "Base Plugin"
    default_severity = "informational"

    def __init__(self, context: PluginContext) -> None:
        self.context = context

    async def run(self) -> list[Finding]:
        return []
