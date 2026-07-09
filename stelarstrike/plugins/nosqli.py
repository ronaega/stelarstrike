"""
NoSQL Injection plugin (MongoDB-flavored operator injection).

Detection strategy: send the same logical parameter as a JSON body with
a `$ne`/`$gt` operator instead of a scalar value, and compare against a
baseline request. A significantly different (usually "more successful")
response indicates the backend passes user-controlled operators
straight into a query filter.
"""

from __future__ import annotations

import json

from stelarstrike.core.report import Finding
from stelarstrike.plugins.base import VulnerabilityPlugin
from stelarstrike.utils.http_client import get_query_params

_NOSQL_ERROR_SIGNATURES = [
    "mongoerror",
    "bsonerror",
    "unknown operator",
    "$where",
    "mongodb.node_driver",
]


class NoSQLiPlugin(VulnerabilityPlugin):
    id = "nosqli"
    name = "NoSQL Injection"
    default_severity = "high"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        params = get_query_params(self.target_url)
        if not params:
            return findings

        for param, value in params.items():
            f = await self._check_operator_injection(param, value)
            if f:
                findings.append(f)

        return findings

    async def _check_operator_injection(self, param: str, value: str) -> Finding | None:
        baseline_body = {param: value}
        injected_body = {param: {"$ne": None}}

        baseline_resp = await self.post(self.target_url, json=baseline_body)
        injected_resp = await self.post(self.target_url, json=injected_body)

        body_lower = injected_resp.text.lower()
        for sig in _NOSQL_ERROR_SIGNATURES:
            if sig in body_lower:
                return self.finding(
                    title="NoSQL Injection (operator error disclosure)",
                    url=self.target_url,
                    parameter=param,
                    evidence=f"Injected body {json.dumps(injected_body)} -> signature '{sig}'",
                    description=(
                        f"Sending a MongoDB query operator as the value of '{param}' "
                        f"surfaced a database-level error, indicating the operator "
                        f"reached the query engine unsanitized."
                    ),
                    remediation="Reject non-scalar input for fields used in query filters; use a schema validator (e.g. Mongoose) that rejects operator keys.",
                    confidence="medium",
                    cwe="CWE-943",
                )

        if (
            injected_resp.status_code == 200
            and baseline_resp.status_code != 200
            and len(injected_resp.text) > len(baseline_resp.text) * 1.5
        ):
            return self.finding(
                title="NoSQL Injection (operator bypass)",
                url=self.target_url,
                parameter=param,
                evidence=(
                    f"Baseline status={baseline_resp.status_code} len={len(baseline_resp.text)}; "
                    f"injected status={injected_resp.status_code} len={len(injected_resp.text)}"
                ),
                description=(
                    f"Replacing '{param}' with a `$ne` operator returned substantially "
                    f"more data than the baseline request, suggesting the operator "
                    f"widened the query filter (e.g. an auth or lookup bypass)."
                ),
                remediation="Whitelist expected value types per field; strip MongoDB operator keys ($ne, $gt, $regex, ...) from user input before querying.",
                confidence="low",
                cwe="CWE-943",
            )
        return None
