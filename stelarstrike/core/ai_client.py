"""
Thin AI wrapper around OPENCODE (Big Pickle).

Why OPENCODE: it gives StelarStrike one interface for high-quality
reasoning models, so switching providers is a one-line change in
config.yaml / .env instead of a code change.

The AI layer is used for three optional roles, each toggle-able in
config.yaml under `ai.roles`:
  - triage:          rank/deduplicate raw findings by real-world exploitability
  - report_writer:   turn structured findings into human-readable narrative
  - payload_advisor: suggest payload variants (only relevant when
                      engagement.allow_active_payloads is true)

If ai.enabled is false, all methods fall back to deterministic,
non-AI behavior so the tool still works fully offline.
"""

from __future__ import annotations

import json
from typing import Any

from stelarstrike.core.config import AIConfig
from stelarstrike.utils.logger import get_logger

log = get_logger(__name__)


class AIClient:
    def __init__(self, config: AIConfig):
        self.config = config
        self._opencode = None
        if self.config.enabled:
            try:
                import opencode  # imported lazily so the tool works without it installed

                self._opencode = opencode
            except ImportError:
                log.warning("opencode not installed; AI features disabled. `pip install opencode`.")
                self.config.enabled = False

    def _complete(self, system: str, user: str) -> str | None:
        if not self.config.enabled or self._opencode is None:
            return None
        try:
            response = self._opencode.complete(
                model=self.config.provider,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
            return response["choices"][0]["message"]["content"]
        except Exception as exc:  # noqa: BLE001 — surfaced to the user, never crashes a scan
            log.error(f"AI call failed ({self.config.provider}): {exc}")
            return None

    def triage_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Rank findings by exploitability/confidence. Falls back to input order."""
        if not self.config.roles.get("triage", False):
            return findings

        prompt = (
            "You are a senior penetration tester triaging automated scan output.\n"
            "Given this JSON list of findings, return a JSON array of the same "
            "findings, each with an added \"priority\" field (critical/high/"
            "medium/low/informational) and a one-sentence \"exploitability_note\".\n"
            "Respond with ONLY the JSON array, no prose.\n\n"
            f"{json.dumps(findings, indent=2)}"
        )
        result = self._complete(
            system="You are a precise security triage assistant. Output valid JSON only.",
            user=prompt,
        )
        if not result:
            return findings
        try:
            cleaned = result.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
            return json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            log.warning("AI triage returned non-JSON output; keeping original ordering.")
            return findings

    def draft_report_narrative(self, engagement_name: str, findings: list[dict[str, Any]]) -> str:
        """Produce an executive-summary style narrative. Falls back to a plain template."""
        if not self.config.roles.get("report_writer", False):
            return self._fallback_narrative(engagement_name, findings)

        prompt = (
            f"Write a concise executive summary (max 200 words) for a penetration "
            f"test report of engagement '{engagement_name}'. Findings (JSON):\n\n"
            f"{json.dumps(findings, indent=2)}\n\n"
            "Tone: professional, factual, no fluff. No markdown headers."
        )
        result = self._complete(
            system="You are a security report writer producing client-ready prose.",
            user=prompt,
        )
        return result or self._fallback_narrative(engagement_name, findings)

    @staticmethod
    def _fallback_narrative(engagement_name: str, findings: list[dict[str, Any]]) -> str:
        by_severity: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
        summary = ", ".join(f"{count} {sev}" for sev, count in sorted(by_severity.items()))
        return (
            f"Engagement '{engagement_name}' identified {len(findings)} finding(s): "
            f"{summary or 'none'}. AI-generated narrative is disabled; enable "
            f"ai.roles.report_writer in config.yaml for a written summary."
        )
