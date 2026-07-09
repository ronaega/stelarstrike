"""
SQL Injection plugin.

Detection strategy (in order, each gated by `techniques` in config):
  - error-based:   inject a single quote, look for DB error signatures in the response
  - boolean-blind:  compare response similarity between a TRUE and FALSE condition
  - time-blind:     compare response latency between a baseline and a delayed condition

This plugin intentionally does NOT extract data. It confirms
injectability and stops — data extraction belongs to a human-reviewed
follow-up step (e.g. sqlmap), consistent with `engagement.allow_active_payloads`.
"""

from __future__ import annotations

import time

from stelarstrike.core.report import Finding
from stelarstrike.plugins.base import VulnerabilityPlugin
from stelarstrike.utils.http_client import build_url_with_params, get_query_params

_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "pg_query():",
    "ora-01756",
    "sqlite3.operationalerror",
]


class SQLiPlugin(VulnerabilityPlugin):
    id = "sqli"
    name = "SQL Injection"
    default_severity = "high"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        params = get_query_params(self.target_url)
        if not params:
            return findings

        techniques = self.options.get("techniques", ["error-based"])

        for param in params:
            if "error-based" in techniques:
                f = await self._check_error_based(param, params)
                if f:
                    findings.append(f)
                    continue  # already confirmed injectable, skip further checks on this param

            if "boolean-blind" in techniques:
                f = await self._check_boolean_blind(param, params)
                if f:
                    findings.append(f)
                    continue

            if "time-blind" in techniques and self.ctx.allow_active_payloads:
                f = await self._check_time_blind(param, params)
                if f:
                    findings.append(f)

        return findings

    async def _check_error_based(self, param: str, params: dict[str, str]) -> Finding | None:
        test_params = dict(params)
        test_params[param] = params[param] + "'"
        url = build_url_with_params(self.target_url, test_params)
        resp = await self.get(url)
        body_lower = resp.text.lower()
        for sig in _ERROR_SIGNATURES:
            if sig in body_lower:
                return self.finding(
                    title="SQL Injection (error-based)",
                    url=self.target_url,
                    parameter=param,
                    evidence=f"Injected {param}=...' -> DB error signature: '{sig}'",
                    description=(
                        f"Parameter '{param}' reflects a database error when a single "
                        f"quote is injected, indicating unsanitized input reaches a SQL query."
                    ),
                    remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                    confidence="high",
                    cwe="CWE-89",
                )
        return None

    async def _check_boolean_blind(self, param: str, params: dict[str, str]) -> Finding | None:
        true_params = dict(params)
        true_params[param] = f"{params[param]}' OR '1'='1"
        false_params = dict(params)
        false_params[param] = f"{params[param]}' AND '1'='2"

        true_resp = await self.get(build_url_with_params(self.target_url, true_params))
        false_resp = await self.get(build_url_with_params(self.target_url, false_params))

        if len(true_resp.text) != len(false_resp.text) and abs(
            len(true_resp.text) - len(false_resp.text)
        ) > 20:
            return self.finding(
                title="SQL Injection (boolean-blind)",
                url=self.target_url,
                parameter=param,
                evidence=(
                    f"TRUE payload response length={len(true_resp.text)}, "
                    f"FALSE payload response length={len(false_resp.text)}"
                ),
                description=(
                    f"Parameter '{param}' produces different response bodies for logically "
                    f"true vs. false injected conditions, suggesting blind SQL injection."
                ),
                remediation="Use parameterized queries / prepared statements.",
                confidence="medium",
                cwe="CWE-89",
            )
        return None

    async def _check_time_blind(self, param: str, params: dict[str, str]) -> Finding | None:
        delay = int(self.options.get("time_delay_seconds", 5))
        baseline_params = dict(params)
        payload_params = dict(params)
        payload_params[param] = f"{params[param]}' OR SLEEP({delay})-- -"

        start = time.monotonic()
        await self.get(build_url_with_params(self.target_url, baseline_params))
        baseline_elapsed = time.monotonic() - start

        start = time.monotonic()
        await self.get(build_url_with_params(self.target_url, payload_params))
        payload_elapsed = time.monotonic() - start

        if payload_elapsed - baseline_elapsed >= delay * 0.8:
            return self.finding(
                title="SQL Injection (time-blind)",
                url=self.target_url,
                parameter=param,
                evidence=f"Baseline={baseline_elapsed:.2f}s, payload={payload_elapsed:.2f}s (delay={delay}s)",
                description=(
                    f"Parameter '{param}' introduces a measurable delay matching the "
                    f"injected SLEEP() duration, indicating time-based blind SQL injection."
                ),
                remediation="Use parameterized queries / prepared statements.",
                confidence="high",
                cwe="CWE-89",
            )
        return None
