"""Report generation: turns a list of Finding objects into markdown/json artifacts."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    plugin: str            # e.g. "sqli"
    title: str              # short human title
    severity: str            # critical | high | medium | low | informational
    url: str
    parameter: str | None = None
    evidence: str | None = None
    description: str = ""
    remediation: str = ""
    confidence: str = "medium"   # low | medium | high | confirmed
    cwe: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    extracted_data: dict | None = None  # structured data from SQLi extraction; JSON report only


class ReportBuilder:
    def __init__(self, engagement_name: str, report_dir: str):
        self.engagement_name = engagement_name
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.findings: list[Finding] = []
        self.narrative: str = ""

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def as_dicts(self) -> list[dict[str, Any]]:
        return [asdict(f) for f in self.findings]

    def write_json(self) -> Path:
        path = self.report_dir / f"{self._slug()}.json"
        payload = {
            "engagement": self.engagement_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "finding_count": len(self.findings),
            "findings": self.as_dicts(),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def write_markdown(self) -> Path:
        path = self.report_dir / f"{self._slug()}.md"
        lines = [
            f"# StelarStrike Report — {self.engagement_name}",
            f"_Generated: {datetime.now(timezone.utc).isoformat()}_",
            "",
            "## Executive Summary",
            "",
            self.narrative or "_No narrative generated._",
            "",
            f"## Findings ({len(self.findings)})",
            "",
        ]
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        for f in sorted(self.findings, key=lambda x: severity_order.get(x.severity, 5)):
            lines += [
                f"### [{f.severity.upper()}] {f.title} ({f.plugin})",
                f"- **URL:** `{f.url}`",
                f"- **Parameter:** `{f.parameter or 'n/a'}`",
                f"- **Confidence:** {f.confidence}",
                f"- **CWE:** {f.cwe or 'n/a'}",
                "",
                f"**Description:** {f.description}",
                "",
                f"**Evidence:**\n```\n{f.evidence or 'n/a'}\n```",
                "",
            ]

            # Add extracted data section if present
            if f.extracted_data:
                lines.append("**Extracted Data:**")
                lines.append("```json")
                lines.append(json.dumps(f.extracted_data, indent=2))
                lines.append("```")
                lines.append("")

            lines += [
                f"**Remediation:** {f.remediation}",
                "",
                "---",
                "",
            ]
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _slug(self) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        safe_name = "".join(c if c.isalnum() else "-" for c in self.engagement_name).strip("-")
        return f"{safe_name}-{stamp}"
