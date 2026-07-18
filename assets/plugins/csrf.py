"""
Cross-Site Request Forgery (CSRF) plugin.

Detection strategy: fetch every state-changing form (method=POST) on
the target page and check for the two standard defenses:
  1. A per-request anti-CSRF token hidden field (heuristically matched
     by field name: csrf, xsrf, authenticity_token, token, nonce, ...)
  2. A `SameSite=Strict|Lax` attribute on session/auth cookies, which
     mitigates CSRF even without a token.

A form missing both is flagged. A form with only SameSite cookie
protection is flagged at lower severity (defense-in-depth gap).
"""

from __future__ import annotations

from assets.core.report import Finding
from assets.plugins.base import VulnerabilityPlugin
from assets.utils.http_client import extract_forms

_TOKEN_FIELD_HINTS = ["csrf", "xsrf", "authenticity_token", "_token", "nonce", "anti-forgery"]


class CSRFPlugin(VulnerabilityPlugin):
    id = "csrf"
    name = "Cross-Site Request Forgery"
    default_severity = "medium"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        resp = await self.get(self.target_url)
        forms = extract_forms(resp.text)

        samesite_ok = self._check_samesite_cookies(resp) if self.options.get("check_samesite", True) else False

        for form in forms:
            if form["method"] != "post":
                continue

            has_token = any(
                any(hint in inp["name"].lower() for hint in _TOKEN_FIELD_HINTS)
                for inp in form["inputs"]
            )

            if has_token:
                continue

            if samesite_ok:
                findings.append(
                    self.finding(
                        title="CSRF: form lacks anti-CSRF token (mitigated by SameSite cookie)",
                        url=self.target_url,
                        parameter=form["action"] or self.target_url,
                        severity="low",
                        confidence="medium",
                        evidence=f"POST form action='{form['action']}' has no token field; session cookie sets SameSite.",
                        description=(
                            "This state-changing form has no per-request CSRF token. "
                            "SameSite cookie attributes provide partial mitigation in "
                            "modern browsers but are not a substitute for token validation "
                            "(e.g. subdomain-hosted attacker content, or older browsers)."
                        ),
                        remediation="Add a per-session or per-request CSRF token validated server-side, in addition to SameSite cookies.",
                        cwe="CWE-352",
                    )
                )
            else:
                findings.append(
                    self.finding(
                        title="CSRF: form lacks anti-CSRF token and SameSite protection",
                        url=self.target_url,
                        parameter=form["action"] or self.target_url,
                        severity="high",
                        confidence="medium",
                        evidence=f"POST form action='{form['action']}' has no token field; no SameSite cookie protection detected.",
                        description=(
                            "This state-changing form has neither a CSRF token nor a "
                            "SameSite-protected session cookie, making it a likely CSRF "
                            "target: a third-party site can trigger this request using "
                            "the victim's authenticated session."
                        ),
                        remediation="Add a per-session or per-request CSRF token validated server-side, and set SameSite=Lax or Strict on session cookies.",
                        cwe="CWE-352",
                    )
                )

        return findings

    @staticmethod
    def _check_samesite_cookies(resp) -> bool:
        set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not set_cookie_headers:
            raw = resp.headers.get("set-cookie", "")
            set_cookie_headers = [raw] if raw else []
        return any("samesite=strict" in h.lower() or "samesite=lax" in h.lower() for h in set_cookie_headers)
