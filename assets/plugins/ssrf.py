"""
Server-Side Request Forgery (SSRF) plugin.

Detection strategy:
  1. Static: flag parameters whose name/value strongly suggest they are
     used as a server-side fetch target (url, uri, path, dest, redirect,
     callback, image, feed, ...) even before sending anything.
  2. Dynamic (only when `collaborator_url` is configured): point the
     candidate parameter at an out-of-band collaborator host (e.g. an
     Interactsh/Burp Collaborator URL you control) and rely on the
     collaborator receiving a callback to confirm server-side fetch.

StelarStrike does not ship a built-in collaborator; wire up your own
(Interactsh, Burp Collaborator, a webhook.site URL you own) and set
`plugins.ssrf.collaborator_url` in config.yaml.
"""

from __future__ import annotations

from assets.core.report import Finding
from assets.plugins.base import VulnerabilityPlugin
from assets.utils.http_client import build_url_with_params, get_query_params

_SUSPICIOUS_PARAM_HINTS = [
    "url", "uri", "path", "dest", "destination", "redirect", "target",
    "callback", "webhook", "image", "img", "feed", "src", "proxy",
    "fetch", "load", "continue", "next", "return_to",
]


class SSRFPlugin(VulnerabilityPlugin):
    id = "ssrf"
    name = "Server-Side Request Forgery"
    default_severity = "high"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        params = get_query_params(self.target_url)
        if not params:
            return findings

        collaborator_url = self.options.get("collaborator_url", "").strip()

        for param, value in params.items():
            is_suspicious_name = any(hint in param.lower() for hint in _SUSPICIOUS_PARAM_HINTS)
            is_url_value = value.startswith("http://") or value.startswith("https://")

            if not (is_suspicious_name or is_url_value):
                continue

            findings.append(
                self.finding(
                    title="Potential SSRF sink (parameter accepts a URL-like value)",
                    url=self.target_url,
                    parameter=param,
                    severity="low",
                    confidence="low",
                    evidence=f"Parameter name/value pattern: {param}={value}",
                    description=(
                        f"Parameter '{param}' looks like it may be used server-side to "
                        f"fetch a resource (by name or by already containing a URL). "
                        f"This is a candidate for manual SSRF testing."
                    ),
                    remediation=(
                        "Maintain an allowlist of permitted destination hosts/schemes for "
                        "any server-side fetch; block requests to RFC1918 ranges, "
                        "link-local (169.254.0.0/16, incl. cloud metadata endpoints), and "
                        "loopback addresses."
                    ),
                    cwe="CWE-918",
                )
            )

            if collaborator_url and self.ctx.allow_active_payloads:
                test_params = dict(params)
                test_params[param] = f"{collaborator_url}/stelarstrike-{param}"
                probe_url = build_url_with_params(self.target_url, test_params)
                await self.get(probe_url)
                findings.append(
                    self.finding(
                        title="SSRF out-of-band probe sent (verify collaborator manually)",
                        url=probe_url,
                        parameter=param,
                        severity="informational",
                        confidence="low",
                        evidence=f"Probe sent to {collaborator_url}/stelarstrike-{param}; check your collaborator dashboard for an inbound hit.",
                        description=(
                            "An out-of-band callback probe was sent through this "
                            "parameter. A hit on your collaborator confirms server-side "
                            "fetch and upgrades this to a confirmed SSRF."
                        ),
                        remediation=(
                            "Maintain an allowlist of permitted destination hosts/schemes; "
                            "block internal/metadata IP ranges."
                        ),
                        cwe="CWE-918",
                    )
                )

        return findings
