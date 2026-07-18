"""
Cross-Site Scripting (XSS) plugin.

Detection strategy: inject a unique, non-executing marker string into
every query parameter and form field, then check whether the marker
is reflected unescaped in the HTML response (i.e. HTML metacharacters
survive). This confirms *reflection* — a strong precondition for XSS —
without firing an actual `<script>` payload, keeping the check safe to
run against production-adjacent targets by default.

Set `engagement.allow_active_payloads: true` to additionally attempt
a canary `<script>` payload and verify it round-trips completely
unescaped (higher-confidence "stored/reflected XSS" finding).
"""

from __future__ import annotations

import uuid

from assets.core.report import Finding
from assets.plugins.base import VulnerabilityPlugin
from assets.utils.http_client import build_url_with_params, extract_forms, get_query_params


class XSSPlugin(VulnerabilityPlugin):
    id = "xss"
    name = "Cross-Site Scripting"
    default_severity = "medium"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        contexts = self.options.get("contexts", ["reflected"])

        if "reflected" in contexts:
            findings += await self._check_reflected_query_params()
            findings += await self._check_reflected_forms()

        return findings

    async def _check_reflected_query_params(self) -> list[Finding]:
        findings: list[Finding] = []
        params = get_query_params(self.target_url)
        for param in params:
            marker = f"stlr{uuid.uuid4().hex[:8]}"
            probe = f"\"'><{marker}"
            test_params = dict(params)
            test_params[param] = probe
            url = build_url_with_params(self.target_url, test_params)

            resp = await self.get(url)
            findings_for_param = self._evaluate_reflection(resp.text, probe, marker, url, param)
            if findings_for_param:
                findings.append(findings_for_param)

            if self.ctx.allow_active_payloads:
                script_marker = f"stlr{uuid.uuid4().hex[:8]}"
                script_probe = f"<script>/*{script_marker}*/</script>"
                test_params[param] = script_probe
                url = build_url_with_params(self.target_url, test_params)
                resp = await self.get(url)
                if script_probe in resp.text:
                    findings.append(
                        self.finding(
                            title="Confirmed Reflected XSS (script payload round-trips unescaped)",
                            url=url,
                            parameter=param,
                            evidence=f"Full payload '{script_probe}' found verbatim in response body.",
                            description=(
                                f"Parameter '{param}' reflects a full <script> tag with no "
                                f"encoding, confirming exploitable reflected XSS."
                            ),
                            remediation="Context-aware output encoding (HTML entity encode on HTML output) plus a strict Content-Security-Policy.",
                            confidence="confirmed",
                            severity="high",
                            cwe="CWE-79",
                        )
                    )
        return findings

    async def _check_reflected_forms(self) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await self.get(self.target_url)
        except Exception:
            return findings

        forms = extract_forms(resp.text)
        for form in forms:
            action = form["action"] or self.target_url
            action_url = action if action.startswith("http") else self.target_url

            for input_field in form["inputs"]:
                if input_field["type"] in ("submit", "button", "hidden", "checkbox", "radio"):
                    continue
                marker = f"stlr{uuid.uuid4().hex[:8]}"
                probe = f"\"'><{marker}"
                data = {i["name"]: i.get("value", "test") for i in form["inputs"]}
                data[input_field["name"]] = probe

                if form["method"] == "post":
                    form_resp = await self.post(action_url, data=data)
                else:
                    form_resp = await self.get(build_url_with_params(action_url, data))

                f = self._evaluate_reflection(
                    form_resp.text, probe, marker, action_url, input_field["name"]
                )
                if f:
                    findings.append(f)
        return findings

    def _evaluate_reflection(
        self, body: str, probe: str, marker: str, url: str, param: str
    ) -> Finding | None:
        if probe in body:
            return self.finding(
                title="Reflected XSS (unescaped HTML metacharacters)",
                url=url,
                parameter=param,
                evidence=f"Injected probe '{probe}' found verbatim in response.",
                description=(
                    f"Parameter '{param}' reflects HTML metacharacters (\", ', <, >) "
                    f"without encoding, which is sufficient to break out of the "
                    f"surrounding HTML context."
                ),
                remediation="Context-aware output encoding plus a strict Content-Security-Policy.",
                confidence="medium",
                cwe="CWE-79",
            )
        if marker in body:
            return self.finding(
                title="Reflected input (partially encoded)",
                url=url,
                parameter=param,
                severity="low",
                evidence=f"Marker '{marker}' reflected but metacharacters were encoded/stripped.",
                description=(
                    f"Parameter '{param}' reflects user input; metacharacters appear "
                    f"encoded in this response but should be manually reviewed for "
                    f"context-specific bypasses (attribute, JS, or URL context)."
                ),
                remediation="Verify encoding is applied consistently for every output context (HTML body, attribute, JS, URL).",
                confidence="low",
                cwe="CWE-79",
            )
        return None
