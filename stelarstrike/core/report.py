from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}


@dataclass
class Finding:
    plugin: str
    title: str
    severity: str
    url: str
    description: str = ""
    evidence: dict[str, object] = field(default_factory=dict)
    remediation: str = ""


class ReportBuilder:
    def __init__(self, engagement_name: str, report_dir: str = "reports") -> None:
        self.engagement_name = engagement_name
        self.report_dir = Path(report_dir)
        self.findings: list[Finding] = []

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def _sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda finding: SEVERITY_ORDER.get(finding.severity.lower(), 99),
        )

    def _report_stem(self) -> str:
        safe_name = self.engagement_name.lower().replace(" ", "-")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"{safe_name}-{timestamp}"

    def write_json(self) -> Path:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        path = self.report_dir / f"{self._report_stem()}.json"
        payload = {
            "engagement_name": self.engagement_name,
            "findings": [asdict(finding) for finding in self._sorted_findings()],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def write_markdown(self) -> Path:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        path = self.report_dir / f"{self._report_stem()}.md"
        lines = [f"# Findings - {self.engagement_name}", ""]

        if not self.findings:
            lines.append("No findings recorded.")
        else:
            for finding in self._sorted_findings():
                lines.extend(
                    [
                        f"## {finding.title}",
                        "",
                        f"- Severity: {finding.severity}",
                        f"- Plugin: {finding.plugin}",
                        f"- URL: {finding.url}",
                        "",
                    ]
                )
                if finding.description:
                    lines.extend([finding.description, ""])

        path.write_text("\n".join(lines), encoding="utf-8")
        return path
