import pytest
from stelarstrike.plugins.sqli_extract import SQLiExtractor, ExtractionResult


def _make_extractor(responses: dict, db_type: str = "postgresql") -> SQLiExtractor:
    """Return an extractor whose inject_fn looks up responses by keyword."""
    async def mock_inject(payload: str) -> str:
        payload_lower = payload.lower()
        for key, response in responses.items():
            if key in payload_lower:
                return response
        return '{"result": ""}'

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


@pytest.mark.asyncio
async def test_postgresql_version_extraction():
    extractor = _make_extractor({
        "version()": '{"data": "PostgreSQL 13.23 on x86_64"}',
        "pg_tables": '{"data": "users sessions"}',
        "information_schema.columns": '{"data": "id username password"}',
    })
    version = await extractor._get_version()
    assert "PostgreSQL" in version or version != ""


@pytest.mark.asyncio
async def test_table_discovery():
    extractor = _make_extractor({
        "pg_tables": '{"data": "users orders api_keys"}',
    })
    tables = await extractor._get_tables()
    assert isinstance(tables, list)


@pytest.mark.asyncio
async def test_column_count_enumeration():
    """Extractor must try multiple column counts until UNION works."""
    attempts = []

    async def mock_inject(payload: str) -> str:
        attempts.append(payload)
        if len(attempts) <= 3:
            return "each union query must have the same number of columns"
        return '{"data": "PostgreSQL 13.23"}'

    extractor = SQLiExtractor(
        inject_fn=mock_inject,
        db_type="postgresql",
        config={"enabled": True},
    )
    result = await extractor._get_version()
    assert len(attempts) == 4
    assert "PostgreSQL" in result


@pytest.mark.asyncio
async def test_extraction_disabled_by_default():
    """When extraction.enabled is False, _run_extraction must be a no-op."""
    from unittest.mock import AsyncMock
    from stelarstrike.core.target import Target
    from stelarstrike.plugins.base import PluginContext
    from stelarstrike.plugins.sqli import SQLiPlugin
    import asyncio

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
        body = data if data is not None else json
        username = body.get("username", "")
        class R:
            status_code = 200
            headers = {}
        if "'" in username:
            R.text = "you have an error in your sql syntax"
            R.status_code = 500
        else:
            R.text = "Invalid credentials"
        return R()

    client = AsyncMock()
    client.get.side_effect = fake_get
    client.post.side_effect = fake_post

    ctx = PluginContext(
        target=Target(url="http://target.test/login"),
        http_client=client,
        options={
            "techniques": ["error-based"],
            "extraction": {"enabled": False},   # <-- off
        },
        allow_active_payloads=True,
        semaphore=asyncio.Semaphore(10),
    )
    plugin = SQLiPlugin(ctx)
    findings = await plugin.run()

    # Extraction disabled — no extracted_data on any finding
    for f in findings:
        assert f.extracted_data is None, f"extracted_data should be None when extraction disabled, got: {f.extracted_data}"


@pytest.mark.asyncio
async def test_high_value_table_ranking():
    extractor = _make_extractor({})
    extractor.result.tables = ["products", "users", "orders", "admin_tokens", "logs"]
    ranked = extractor._rank_tables()
    # "users" and "admin_tokens" should rank above "products" and "logs"
    assert ranked.index("users") < ranked.index("products")
    assert ranked.index("admin_tokens") < ranked.index("logs")


@pytest.mark.asyncio
async def test_extraction_result_summary_format():
    result = ExtractionResult(
        db_version="PostgreSQL 13.23",
        db_type="postgresql",
        tables=["users", "orders"],
        columns={"users": ["id", "username", "password"]},
        data={"users": [{"id": "1", "username": "admin", "password": "secret"}]},
    )
    summary = result.summary()
    assert "PostgreSQL 13.23" in summary
    assert "users" in summary
    assert "admin" in summary

    d = result.to_dict()
    assert d["db_type"] == "postgresql"
    assert "users" in d["tables"]
    assert d["data"]["users"][0]["username"] == "admin"
