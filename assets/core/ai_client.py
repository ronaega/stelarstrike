"""
AI client for StelarStrike — powered by OpenCode.

OpenCode (https://opencode.ai) is the AI backend. Install it once:
  curl -fsSL https://opencode.ai/install | bash

Default model: opencode/big-pickle
All AI calls go through `opencode run --format json`, which is the
non-interactive CLI mode. Responses are NDJSON (one JSON event per line).

If OpenCode is not installed or not in PATH, AI features degrade
gracefully: scans still run fully, findings are still reported,
reports just skip the narrative and triage.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from assets.core.config import AIConfig
from assets.utils.logger import get_logger

log = get_logger(__name__)

# Model string for opencode/big-pickle — the default
DEFAULT_MODEL = "opencode/big-pickle"


class AIClient:
    def __init__(self, config: AIConfig):
        self.config = config
        self._opencode_path: str | None = None
        if self.config.enabled:
            self._opencode_path = shutil.which("opencode")
            if not self._opencode_path:
                log.warning(
                    "OpenCode not found in PATH — AI features disabled. "
                    "Install with: curl -fsSL https://opencode.ai/install | bash"
                )
                self.config.enabled = False

    @property
    def model(self) -> str:
        return self.config.provider or DEFAULT_MODEL

    def complete(self, system: str, user: str, timeout: int = 60) -> str | None:
        """
        Run a single prompt through OpenCode and return the response text.
        Uses `opencode run --format json` for non-interactive output.
        Returns None if OpenCode is unavailable or the call fails.
        """
        if not self.config.enabled or not self._opencode_path:
            return None

        prompt = f"{system}\n\n{user}" if system else user

        cmd = [
            self._opencode_path,
            "run",
            "--model", self.model,
            "--format", "json",
            prompt,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return self._parse_response(result.stdout)
        except subprocess.TimeoutExpired:
            log.warning(f"AI: OpenCode timed out after {timeout}s")
        except FileNotFoundError:
            log.warning("AI: opencode binary not found")
        except Exception as exc:  # noqa: BLE001
            log.error(f"AI: OpenCode call failed: {exc}")
        return None

    @staticmethod
    def _parse_response(ndjson_output: str) -> str | None:
        """
        Parse NDJSON event stream from `opencode run --format json`.
        Collects all text/content events and concatenates them.
        """
        if not ndjson_output:
            return None

        text_parts: list[str] = []
        for line in ndjson_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_type = event.get("type", "")

            if event_type == "error":
                err = event.get("error", {})
                log.debug(f"AI: OpenCode error event: {err.get('data', {}).get('message', err)}")
                return None

            # Collect text from various event formats
            if event_type in ("text", "content", "message_delta"):
                text = (
                    event.get("text")
                    or event.get("content")
                    or event.get("delta", {}).get("text", "")
                )
                if text:
                    text_parts.append(str(text))
            elif event_type == "assistant":
                content = event.get("content", "")
                if isinstance(content, str) and content:
                    text_parts.append(content)
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            text_parts.append(block.get("text", ""))

        result = "".join(text_parts).strip()
        return result if result else None

    # ─────────────────────────────────────────────────────────────────────────
    # Higher-level methods used by orchestrator and sqli plugin
    # ─────────────────────────────────────────────────────────────────────────

    def triage_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not self.config.roles.get("triage", False) or not findings:
            return findings

        result = self.complete(
            system="You are a senior pentester triaging findings. Output valid JSON only.",
            user=(
                "Add a 'priority' field (critical/high/medium/low/informational) and "
                "a one-sentence 'exploitability_note' to each finding. "
                "Return ONLY the JSON array, no prose.\n\n"
                + json.dumps(findings, indent=2)
            ),
        )
        if not result:
            return findings
        try:
            cleaned = result.strip().lstrip("```json").lstrip("```").rstrip("```")
            return json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            return findings

    def draft_report_narrative(self, engagement_name: str, findings: list[dict[str, Any]]) -> str:
        if not self.config.roles.get("report_writer", False):
            return self._fallback_narrative(engagement_name, findings)

        result = self.complete(
            system="You are a security report writer. Produce concise professional prose.",
            user=(
                f"Write a 150-word executive summary for pentest engagement "
                f"'{engagement_name}'. Findings:\n\n"
                + json.dumps(findings, indent=2)
                + "\n\nTone: professional, factual. No markdown headers."
            ),
        )
        return result or self._fallback_narrative(engagement_name, findings)

    def sqli_agent_suggest(
        self, history: list[dict], db_type: str, context: str
    ) -> dict | None:
        """
        Iterative SQLi agent: given full probe history, propose ONE next
        payload to try. Returns dict with keys:
          payload, col_count, position, comment, reasoning
        """
        if not self.config.enabled or not self._opencode_path:
            return None

        history_text = "\n\n".join(
            f"Round {i+1}: {h.get('payload', '')[:80]!r}\n"
            f"  result: differs={h.get('differs')}, reflected={h.get('reflected')}\n"
            f"  response: {h.get('snippet', '')[:200]}"
            for i, h in enumerate(history[-8:])
        )

        result = self.complete(
            system=(
                "You are an expert SQL injection pentester. You analyse probe results "
                "and propose the single best next payload to try. Respond in JSON only."
            ),
            user=(
                f"Target DB: {db_type}\nContext: {context}\n\n"
                f"Probe history:\n{history_text or '(none yet)'}\n\n"
                "The app may hide SQL errors. Consider: wider column ranges (up to 20), "
                "different comment styles (--, -- -, #), different quote contexts.\n\n"
                'Respond ONLY with: {"payload": "<SQL suffix>", "col_count": N, '
                '"position": N, "comment": "<style>", "reasoning": "<one sentence>"}'
            ),
            timeout=45,
        )
        if not result:
            return None
        try:
            cleaned = result.strip().lstrip("```json").lstrip("```").rstrip("```")
            return json.loads(cleaned.strip())
        except (json.JSONDecodeError, ValueError):
            return None

    @staticmethod
    def _fallback_narrative(engagement_name: str, findings: list[dict[str, Any]]) -> str:
        by_sev: dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "unknown")
            by_sev[s] = by_sev.get(s, 0) + 1
        summary = ", ".join(f"{c} {s}" for s, c in sorted(by_sev.items()))
        return (
            f"Engagement '{engagement_name}' found {len(findings)} finding(s): "
            f"{summary or 'none'}. Install OpenCode to enable AI-written narratives."
        )
