"""
Tests for the Big Pickle SQLi plugin.

Tests cover the core detection mechanisms — error-based, auth bypass,
UNION column count enumeration, and reflected column detection — using
lightweight mocked HTTP responses.
"""
from __future__ import annotations

import asyncio
import json as _json

import pytest
from unittest.mock import AsyncMock

from assets.core.target import Target
from assets.plugins.base import PluginContext
from assets.plugins.sqli import SQLiPlugin
from assets.skills.sqli_skill import (
    AUTH_BYPASS_PAYLOADS,
    COMMON_ENDPOINTS,
    DB_ERROR_SIGNATURES,
)


def _make_ctx(client: AsyncMock, url: str, allow_active: bool = True) -> PluginContext:
    return PluginContext(
        target=Target(url=url),
        http_client=client,
        options={"max_tables": 3},
        allow_active_payloads=allow_active,
        semaphore=asyncio.Semaphore(10),
    )


def _resp(body: str | dict, status: int = 200):
    class R:
        status_code = status
        text = body if isinstance(body, str) else _json.dumps(body)
        headers = {}
    return R()


# ── skill sanity checks ────────────────────────────────────────────────────

def test_skill_has_expected_endpoints():
    paths = [ep["path"] for ep in COMMON_ENDPOINTS]
    assert "/login" in paths
    assert "/register" in paths
    assert "/api/v3/forgot-password" in paths
    assert "/api/v1/merchants/login" in paths


def test_skill_auth_bypass_includes_big_pickle_payloads():
    assert "admin'--" in AUTH_BYPASS_PAYLOADS
    assert "' OR 1=1--" in AUTH_BYPASS_PAYLOADS


def test_skill_error_signatures_cover_major_dbs():
    sigs = DB_ERROR_SIGNATURES
    assert any("mysql" in s for s in sigs)
    assert any("syntax" in s for s in sigs)
    assert any("pg_query" in s or "postgresql" in s or "unterminated" in s for s in sigs)


# ── error-based detection ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_error_based_detection():
    """Single-quote injection triggers a DB error → high-confidence finding."""
    async def fake_get(url, *a, **kw):
        return _resp("Welcome")

    async def fake_post(url, json=None, data=None, *a, **kw):
        body = json or data or {}
        if "'" in body.get("username", ""):
            return _resp("you have an error in your sql syntax near line 1", 500)
        return _resp({"message": "Invalid credentials"})

    client = AsyncMock()
    client.get.side_effect = fake_get
    client.post.side_effect = fake_post

    plugin = SQLiPlugin(_make_ctx(client, "http://target.test/"))
    findings = await plugin.run()

    error_findings = [f for f in findings if "error-based" in f.title.lower()]
    assert len(error_findings) >= 1
    assert error_findings[0].severity == "high"
    assert error_findings[0].confidence == "high"


# ── auth bypass detection ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_auth_bypass_detection():
    """Auth bypass payload returns JWT → critical finding."""
    async def fake_get(url, *a, **kw):
        return _resp("Welcome")

    async def fake_post(url, json=None, data=None, *a, **kw):
        body = json or data or {}
        username = body.get("username", "")
        if username in ("admin'--", "' OR 1=1--"):
            return _resp({"token": "eyJhbGciOiJIUzI1NiJ9.payload.sig", "user_id": 1}, 200)
        return _resp({"message": "Invalid credentials"}, 200)

    client = AsyncMock()
    client.get.side_effect = fake_get
    client.post.side_effect = fake_post

    plugin = SQLiPlugin(_make_ctx(client, "http://target.test/"))
    findings = await plugin.run()

    bypass = [f for f in findings if "bypass" in f.title.lower()]
    assert len(bypass) >= 1
    assert bypass[0].severity == "critical"
    assert bypass[0].confidence == "confirmed"


# ── UNION column count enumeration ────────────────────────────────────────

@pytest.mark.asyncio
async def test_union_column_count_enumeration():
    """
    Simulates a target that shows 'each UNION query must have the same
    number of columns' for wrong counts and stops on count=10 (Big Pickle's target).
    """
    TARGET_COLS = 10

    async def fake_get(url, *a, **kw):
        return _resp("Welcome")

    async def fake_post(url, json=None, data=None, *a, **kw):
        body = json or data or {}
        username = body.get("username", "")
        if "admin'--" in username or "OR 1=1" in username:
            return _resp({"token": "eyJ..."}, 200)
        if "UNION SELECT" in username.upper():
            nulls = username.upper().count("NULL")
            if nulls != TARGET_COLS:
                return _resp({"error": "each UNION query must have the same number of columns"}, 500)
            return _resp({"message": "ok"}, 200)
        return _resp({"message": "Invalid credentials"}, 200)

    client = AsyncMock()
    client.get.side_effect = fake_get
    client.post.side_effect = fake_post

    plugin = SQLiPlugin(_make_ctx(client, "http://target.test/"))
    col_count, comment = await plugin._find_col_count(
        "http://target.test/login", "post", "json",
        ["username", "password"], "username",
        '{"message": "Invalid credentials"}',
    )
    assert col_count == TARGET_COLS


# ── reflected column detection ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_reflected_column_detection():
    """
    Simulates the MerdekaBank case: column 2 (index 1, the username field)
    is the one reflected in the JSON response.
    """
    REFLECTED_POS = 1
    PROBE_MARKER = "STELRPROBE"

    async def fake_get(url, *a, **kw):
        return _resp("Welcome")

    async def fake_post(url, json=None, data=None, *a, **kw):
        body = json or data or {}
        username = body.get("username", "")
        if PROBE_MARKER in username.upper():
            parts = username.upper().split(",")
            for i, part in enumerate(parts):
                if PROBE_MARKER in part and i == REFLECTED_POS:
                    return _resp({"username": PROBE_MARKER, "token": "eyJ..."}, 200)
        return _resp({"message": "ok"}, 200)

    client = AsyncMock()
    client.get.side_effect = fake_get
    client.post.side_effect = fake_post

    plugin = SQLiPlugin(_make_ctx(client, "http://target.test/"))
    reflected = await plugin._find_reflected_col(
        "http://target.test/login", "post", "json",
        ["username", "password"], "username",
        10, "--",
    )
    assert reflected == REFLECTED_POS


# ── passive mode: no extraction without allow_active_payloads ─────────────

@pytest.mark.asyncio
async def test_passive_mode_skips_union_extraction():
    """With allow_active_payloads=False, UNION steps should not run."""
    post_calls = []

    async def fake_get(url, *a, **kw):
        return _resp("Welcome")

    async def fake_post(url, json=None, data=None, *a, **kw):
        body = json or data or {}
        post_calls.append(body)
        if "'" in body.get("username", ""):
            return _resp("sql syntax error", 500)
        return _resp({"message": "fail"})

    client = AsyncMock()
    client.get.side_effect = fake_get
    client.post.side_effect = fake_post

    plugin = SQLiPlugin(_make_ctx(client, "http://target.test/", allow_active=False))
    await plugin.run()

    union_payloads = [c for c in post_calls if "UNION" in str(c).upper()]
    assert len(union_payloads) == 0, "UNION payloads should not be sent in passive mode"


# ── DB fingerprinting ──────────────────────────────────────────────────────

def test_db_fingerprint_postgresql():
    assert SQLiPlugin._fingerprint_db("pg_query(): ERROR: syntax error at or near") == "postgresql"


def test_db_fingerprint_mysql():
    assert SQLiPlugin._fingerprint_db("warning: mysql_fetch_array()") == "mysql"


def test_db_fingerprint_default():
    assert SQLiPlugin._fingerprint_db("something generic with no clear signal") == "postgresql"
