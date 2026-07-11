"""
Tests for the SQLi extraction engine (sqli_extract.py).

All mocks return sentinel-wrapped values (STELR0...0RLETS) so they
simulate what a real vulnerable app would reflect back — the sentinel
is what makes extraction reliable against HTML responses.
"""
import asyncio

import pytest

from stelarstrike.plugins.sqli_extract import SQLiExtractor, ExtractionResult


S = SQLiExtractor._SENTINEL_START  # "STELR0"
E = SQLiExtractor._SENTINEL_END    # "0RLETS"


def _wrap(value: str) -> str:
    """Simulate what the DB would echo back in the HTML."""
    return f"<html><body><p>{S}{value}{E}</p></body></html>"


def _make_extractor(responses: dict, db_type: str = "postgresql") -> SQLiExtractor:
    """
    Build an extractor whose inject_fn responds based on keywords in the payload.
    `responses` maps a keyword (lowercased) to the HTML string to return.
    Default response: column count mismatch (forces retry).
    """
    async def mock_inject(payload: str) -> str:
        payload_lower = payload.lower()
        for key, response in responses.items():
            if key in payload_lower:
                return response
        # Default: mismatch — forces the extractor to try more column counts
        return "each union query must have the same number of columns"

    return SQLiExtractor(
        inject_fn=mock_inject,
        db_type=db_type,
        config={
            "enabled": True,
            "max_tables": 5,
            "max_columns_per_table": 10,
            "max_rows_per_table": 10,
            "extract": ["version", "schema"],
        },
    )


# ── sentinel extraction ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_extract_value_finds_sentinel_in_html():
    extractor = _make_extractor({})
    html = f"<html><nav>Home Products</nav><p>{S}PostgreSQL 13.23{E}</p></html>"
    result = extractor._extract_value(html)
    assert result == "PostgreSQL 13.23"


@pytest.mark.asyncio
async def test_extract_value_ignores_non_sentinel_html_noise():
    extractor = _make_extractor({})
    # No sentinel — should not grab random nav/CSS text
    html = "<html><nav>Home Products About Contact</nav><p>Welcome user</p></html>"
    result = extractor._extract_value(html)
    # Should be empty — not guessing at nav text
    assert result == "" or len(result) < 50


# ── version extraction ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_postgresql_version_extraction():
    extractor = _make_extractor({
        "version()": _wrap("PostgreSQL 13.23 on x86_64"),
    })
    version = await extractor._get_version()
    assert "PostgreSQL" in version
    assert "13.23" in version


@pytest.mark.asyncio
async def test_mysql_version_extraction():
    extractor = _make_extractor({
        "version()": _wrap("8.0.32-MySQL Community Server"),
    }, db_type="mysql")
    version = await extractor._get_version()
    assert "8.0.32" in version


# ── column count enumeration ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_column_count_enumeration_retries_until_match():
    """Extractor must retry column counts until UNION succeeds."""
    attempts = []

    async def mock_inject(payload: str) -> str:
        attempts.append(payload)
        count = len(attempts)
        if count <= 3:
            return "each union query must have the same number of columns"
        return _wrap("PostgreSQL 13.23")

    extractor = SQLiExtractor(
        inject_fn=mock_inject,
        db_type="postgresql",
        config={"enabled": True, "extract": ["version"]},
    )
    result = await extractor._get_version()
    assert len(attempts) >= 4
    assert "PostgreSQL" in result
    # Column count should now be cached
    assert extractor._col_count is not None


@pytest.mark.asyncio
async def test_cached_column_count_used_on_subsequent_calls():
    calls = []

    async def mock_inject(payload: str) -> str:
        calls.append(payload)
        # Succeed on first call regardless of column count
        return _wrap("somevalue")

    extractor = SQLiExtractor(
        inject_fn=mock_inject,
        db_type="postgresql",
        config={"enabled": True},
    )
    extractor._col_count = 3  # pre-set cache
    result = await extractor._union_scalar("(SELECT 'test')")
    # Should have called inject exactly once (no retry loop)
    assert len(calls) == 1
    assert result == "somevalue"


# ── table and column discovery ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_table_discovery_parses_space_separated_names():
    extractor = _make_extractor({
        "pg_tables": _wrap("users orders products api_keys"),
    })
    tables = await extractor._get_tables()
    assert "users" in tables
    assert "orders" in tables
    assert "api_keys" in tables


@pytest.mark.asyncio
async def test_column_discovery():
    extractor = _make_extractor({
        "information_schema.columns": _wrap("id username email password created_at"),
    })
    extractor._col_count = 1
    cols = await extractor._get_columns("users")
    assert "username" in cols
    assert "password" in cols


# ── compat cols ──────────────────────────────────────────────────────────────

def test_compat_cols_uses_null_for_all_dbs():
    for db_type in ("postgresql", "mysql", "mssql", "sqlite"):
        extractor = _make_extractor({}, db_type=db_type)
        result = extractor._compat_cols(3)
        assert result == "NULL,NULL,NULL", f"Expected NULL padding for {db_type}, got: {result}"


def test_compat_cols_empty_for_zero():
    extractor = _make_extractor({})
    assert extractor._compat_cols(0) == ""


# ── table ranking ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_high_value_table_ranking():
    extractor = _make_extractor({})
    extractor.result.tables = ["products", "users", "orders", "admin_tokens", "logs"]
    ranked = extractor._rank_tables()
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
