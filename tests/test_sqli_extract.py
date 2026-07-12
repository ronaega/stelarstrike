"""
Tests for the SQLi extraction engine — two-phase-aware mocks.

The two-phase approach:
  Phase 1: NULL-only probe to confirm column count (type-safe)
  Phase 2: Sentinel in each position to find the reflected column

Mocks simulate a realistic target:
  - Returns column-mismatch error for wrong column counts
  - Returns type-error when sentinel is in wrong-typed position (e.g. integer id)
  - Reflects the sentinel in the JSON username field (position 1 of 10)
"""
import asyncio
import re as _re

import pytest

from stelarstrike.plugins.sqli_extract import SQLiExtractor, ExtractionResult

S = SQLiExtractor._SENTINEL_START   # "STELR0"
E = SQLiExtractor._SENTINEL_END     # "0RLETS"


def _wrap(value: str) -> str:
    """Simulate what the DB echoes back in the response."""
    return f'{{"username": "{S}{value}{E}", "token": "eyJ..."}}'


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_preconfigured_extractor(inject_responses: dict, db_type: str = "postgresql") -> SQLiExtractor:
    """
    Extractor with col_count=1, reflected_col=0 pre-cached — bypasses discovery.
    inject_responses maps a keyword → response body.
    """
    async def mock_inject(payload: str) -> str:
        payload_lower = payload.lower()
        for key, response in inject_responses.items():
            if key in payload_lower:
                return response
        return f'{{"username": "", "error": "no match for: {payload[:40]}"}}'

    ext = SQLiExtractor(
        inject_fn=mock_inject,
        db_type=db_type,
        config={"enabled": True, "max_tables": 5, "max_rows_per_table": 10,
                "extract": ["version", "schema"]},
    )
    ext._col_count = 1
    ext._reflected_col = 0
    return ext


def _make_discovery_extractor(col_count: int, reflected_pos: int,
                              db_type: str = "postgresql") -> SQLiExtractor:
    """
    Extractor that simulates full two-phase discovery.
    `sentinel_response_fn(subquery_value) -> response_str` is called when
    the sentinel lands on the right position.
    """
    MISMATCH = "each union query must have the same number of columns"
    TYPE_ERR = "invalid input syntax for type integer"

    async def mock_inject(payload: str) -> str:
        p = payload.lower()

        # Count columns in the UNION SELECT clause
        m = _re.search(r"union select (.+?)(?:--|#|$)", p)
        if not m:
            return '{"error": "no union"}'
        cols_str = m.group(1)
        cols = [c.strip() for c in cols_str.split(",")]
        n = len(cols)

        if n != col_count:
            return f'{{"error": "{MISMATCH}"}}'

        # NULL-only probe (phase 1) — just confirm the column count
        if all(c == "null" for c in cols):
            return '{"message": "null probe ok"}'

        # Sentinel probe (phase 2) — check which position has the sentinel
        for i, col in enumerate(cols):
            if s.lower() in col:
                if i == reflected_pos:
                    # Extract the subquery from the sentinel wrapper
                    return _wrap(f"extracted_value_{i}")
                elif i == 0 and reflected_pos != 0:
                    return f'{{"error": "{TYPE_ERR}"}}'
                else:
                    return '{"message": "not reflected here"}'

        return '{"message": "ok"}'

    s = S.lower()
    ext = SQLiExtractor(
        inject_fn=mock_inject,
        db_type=db_type,
        config={"enabled": True, "max_tables": 5, "max_rows_per_table": 10,
                "extract": ["version", "schema"]},
    )
    return ext


# ── sentinel extraction ───────────────────────────────────────────────────────

def test_extract_value_finds_sentinel_in_json():
    ext = _make_preconfigured_extractor({})
    json_resp = f'{{"username": "{S}PostgreSQL 13.23{E}", "token": "eyJ..."}}'
    result = ext._extract_value(json_resp)
    assert result == "PostgreSQL 13.23"


def test_extract_value_finds_sentinel_in_html():
    ext = _make_preconfigured_extractor({})
    html = f"<html><nav>Home Products About</nav><p>{S}PostgreSQL 13.23{E}</p></html>"
    result = ext._extract_value(html)
    assert result == "PostgreSQL 13.23"


def test_extract_value_empty_when_no_sentinel():
    ext = _make_preconfigured_extractor({})
    result = ext._extract_value("<html><body>Login failed. Invalid credentials.</body></html>")
    assert result == ""


# ── two-phase discovery ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_discovery_finds_correct_col_count_and_position():
    """10-column table, reflected at position 1 — matches MerdekaBank."""
    ext = _make_discovery_extractor(col_count=10, reflected_pos=1)
    found = await ext._find_col_count_and_position(
        wrapped=f"'{S}'||(version())||'{E}'",
        comment="-- -",
    )
    assert found is True
    assert ext._col_count == 10
    assert ext._reflected_col == 1


@pytest.mark.asyncio
async def test_discovery_finds_col_count_3_position_0():
    """3-column table, reflected at position 0 — simple case."""
    ext = _make_discovery_extractor(col_count=3, reflected_pos=0)
    found = await ext._find_col_count_and_position(
        wrapped=f"'{S}'||(version())||'{E}'",
        comment="-- -",
    )
    assert found is True
    assert ext._col_count == 3
    assert ext._reflected_col == 0


@pytest.mark.asyncio
async def test_discovery_type_error_forces_next_position():
    """
    Simulate position 0 as INTEGER (type error), position 1 as TEXT (reflected).
    The extractor should skip 0 and find 1.
    """
    TYPE_ERR = "invalid input syntax for type integer"
    MISMATCH = "each union query must have the same number of columns"

    async def mock_inject(payload: str) -> str:
        p = payload.lower()
        m = _re.search(r"union select (.+?)(?:--|#|$)", p)
        if not m:
            return '{"error": "no union"}'
        cols = [c.strip() for c in m.group(1).split(",")]
        if len(cols) != 3:
            return f'{{"error": "{MISMATCH}"}}'
        if all(c == "null" for c in cols):
            return '{"ok": true}'
        for i, c in enumerate(cols):
            if "stelr0" in c:
                if i == 0:
                    return f'{{"error": "{TYPE_ERR}"}}'
                if i == 1:
                    return _wrap("extracted_value")
        return '{"message": "nothing reflected"}'

    ext = SQLiExtractor(
        inject_fn=mock_inject,
        db_type="postgresql",
        config={"enabled": True},
    )
    found = await ext._find_col_count_and_position(f"'{S}'||(version())||'{E}'", "-- -")
    assert found is True
    assert ext._reflected_col == 1


# ── version extraction ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_postgresql_version_extraction():
    ext = _make_preconfigured_extractor({
        "version()": _wrap("PostgreSQL 13.23 on x86_64"),
    })
    version = await ext._get_version()
    assert "PostgreSQL" in version
    assert "13.23" in version


@pytest.mark.asyncio
async def test_mysql_version_extraction():
    ext = _make_preconfigured_extractor({
        "version()": _wrap("8.0.32-MySQL Community Server"),
    }, db_type="mysql")
    version = await ext._get_version()
    assert "8.0.32" in version


# ── table discovery ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_table_discovery_parses_space_separated_names():
    ext = _make_preconfigured_extractor({
        "pg_tables": _wrap("users orders products api_keys"),
    })
    tables = await ext._get_tables()
    assert "users" in tables
    assert "orders" in tables
    assert "api_keys" in tables


@pytest.mark.asyncio
async def test_column_discovery():
    ext = _make_preconfigured_extractor({
        "information_schema.columns": _wrap("id username email password created_at"),
    })
    cols = await ext._get_columns("users")
    assert "username" in cols
    assert "password" in cols


# ── cached position reuse ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cached_col_count_and_position_used_on_subsequent_call():
    calls = []

    async def mock_inject(payload: str) -> str:
        calls.append(payload)
        return _wrap("somevalue")

    ext = SQLiExtractor(
        inject_fn=mock_inject,
        db_type="postgresql",
        config={"enabled": True},
    )
    ext._col_count = 3
    ext._reflected_col = 1  # both must be set to skip discovery
    result = await ext._union_scalar("(SELECT 'test')")
    assert len(calls) == 1, f"Expected 1 call (cached), got {len(calls)}"
    assert result == "somevalue"


# ── compat cols ───────────────────────────────────────────────────────────────

def test_compat_cols_uses_null_for_all_dbs():
    for db_type in ("postgresql", "mysql", "mssql", "sqlite"):
        ext = _make_preconfigured_extractor({}, db_type=db_type)
        assert ext._compat_cols(3) == "NULL,NULL,NULL"


def test_compat_cols_empty_for_zero():
    ext = _make_preconfigured_extractor({})
    assert ext._compat_cols(0) == ""


# ── table ranking ─────────────────────────────────────────────────────────────

def test_high_value_table_ranking():
    ext = _make_preconfigured_extractor({})
    ext.result.tables = ["products", "users", "orders", "admin_tokens", "logs"]
    ranked = ext._rank_tables()
    assert ranked.index("users") < ranked.index("products")
    assert ranked.index("admin_tokens") < ranked.index("logs")


# ── extraction disabled ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_extraction_disabled_produces_no_extracted_data():
    from unittest.mock import AsyncMock
    from stelarstrike.core.target import Target
    from stelarstrike.plugins.base import PluginContext
    from stelarstrike.plugins.sqli import SQLiPlugin

    LOGIN_PAGE = """<html><body>
    <form method="post" action="/login">
    <input name="username"><input name="password" type="password">
    <input type="submit"></form></body></html>"""

    async def fake_get(url, *a, **kw):
        class R:
            text = LOGIN_PAGE
            status_code = 200
        return R()

    async def fake_post(url, data=None, json=None, *a, **kw):
        body = data if data is not None else (json or {})
        username = body.get("username", "")
        class R:
            headers = {}
        if "'" in username:
            R.text = "you have an error in your sql syntax"
            R.status_code = 500
        else:
            R.text = "Invalid credentials"
            R.status_code = 200
        return R()

    client = AsyncMock()
    client.get.side_effect = fake_get
    client.post.side_effect = fake_post

    ctx = PluginContext(
        target=Target(url="http://target.test/login"),
        http_client=client,
        options={"techniques": ["error-based"], "extraction": {"enabled": False}},
        allow_active_payloads=True,
        semaphore=asyncio.Semaphore(10),
    )
    findings = await SQLiPlugin(ctx).run()
    for f in findings:
        assert f.extracted_data is None


# ── result formatting ─────────────────────────────────────────────────────────

def test_extraction_result_summary_and_dict():
    result = ExtractionResult(
        db_version="PostgreSQL 13.23",
        db_type="postgresql",
        tables=["users", "orders"],
        columns={"users": ["id", "username", "password"]},
        data={"users": [{"id": "1", "username": "admin", "password": "hunter2"}]},
    )
    summary = result.summary()
    assert "PostgreSQL 13.23" in summary
    assert "users" in summary
    assert "admin" in summary

    d = result.to_dict()
    assert d["db_type"] == "postgresql"
    assert "users" in d["tables"]
    assert d["data"]["users"][0]["username"] == "admin"
