"""
Insecure Direct Object Reference (IDOR) plugin.

Detection strategy: locate parameters whose name matches common
identifier hints (id, user_id, account, order_id, ...) and whose value
looks like a sequential/enumerable identifier (integer or UUID). For
each candidate, request a neighboring identifier (n-1, n+1 for
integers) using the SAME session/credentials the scan is running with.

A 200 response with a body that differs from a clearly-invalid ID
probe (very high/negative ID) suggests the endpoint returns data for
IDs beyond what the current session should be able to access —
authorization must be verified manually to confirm actual horizontal
privilege escalation, since StelarStrike does not assume multi-account
credentials are configured.
"""

from __future__ import annotations

import re

from assets.core.report import Finding
from assets.plugins.base import VulnerabilityPlugin
from assets.utils.http_client import build_url_with_params, get_query_params

_INT_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


class IDORPlugin(VulnerabilityPlugin):
    id = "idor"
    name = "Insecure Direct Object Reference"
    default_severity = "high"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        params = get_query_params(self.target_url)
        hints = [h.lower() for h in self.options.get("id_param_hints", ["id"])]

        for param, value in params.items():
            if not any(hint in param.lower() for hint in hints):
                continue

            if _INT_RE.match(value):
                f = await self._check_integer_id(param, params, int(value))
            elif _UUID_RE.match(value):
                f = self._flag_uuid_candidate(param, value)
            else:
                continue

            if f:
                findings.append(f)

        return findings

    async def _check_integer_id(self, param: str, params: dict[str, str], value: int) -> Finding | None:
        baseline_resp = await self.get(build_url_with_params(self.target_url, params))
        if baseline_resp.status_code >= 400:
            return None

        neighbor_params = dict(params)
        neighbor_id = value - 1 if value > 1 else value + 1
        neighbor_params[param] = str(neighbor_id)
        neighbor_url = build_url_with_params(self.target_url, neighbor_params)
        neighbor_resp = await self.get(neighbor_url)

        if (
            neighbor_resp.status_code == 200
            and neighbor_resp.text.strip()
            and neighbor_resp.text != baseline_resp.text
        ):
            return self.finding(
                title="Potential IDOR: sequential identifier returns data for a different object",
                url=neighbor_url,
                parameter=param,
                confidence="low",
                evidence=(
                    f"'{param}={value}' -> HTTP {baseline_resp.status_code}; "
                    f"'{param}={neighbor_id}' (current session/credentials unchanged) -> "
                    f"HTTP {neighbor_resp.status_code} with a different, non-empty body."
                ),
                description=(
                    f"Requesting a neighboring value of '{param}' with the same "
                    f"session returned a distinct, non-empty response. This is "
                    f"consistent with missing per-object authorization checks, but "
                    f"must be manually verified against a second, lower-privileged "
                    f"account to confirm actual horizontal access."
                ),
                remediation=(
                    "Enforce object-level authorization on every request (verify the "
                    "authenticated principal owns/may access the referenced object "
                    "server-side); prefer indirect references (per-user opaque tokens) "
                    "over raw sequential IDs."
                ),
                cwe="CWE-639",
            )
        return None

    def _flag_uuid_candidate(self, param: str, value: str) -> Finding:
        return self.finding(
            title="IDOR candidate: object referenced by UUID (manual authorization review needed)",
            url=self.target_url,
            parameter=param,
            severity="informational",
            confidence="low",
            evidence=f"{param}={value}",
            description=(
                f"Parameter '{param}' references an object by UUID. UUIDs are not "
                f"enumerable, which reduces (but does not eliminate) IDOR risk — "
                f"authorization must still be checked server-side. Manually test with "
                f"a second account's UUID to confirm access control is enforced."
            ),
            remediation="Ensure every object-referencing endpoint performs a server-side ownership/permission check regardless of reference type.",
            cwe="CWE-639",
        )
