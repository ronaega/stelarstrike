"""
Tests for the SQLi extraction engine.

Covers:
  - Baseline-diff detection (works even when the target silently
    swallows every SQL error and shows no distinguishing text)
  - Multi-comment-style / multi-context probing
  - The iterative AI agent loop (multi-round, not one-shot)
  - Markdown table rendering
"""
import asyncio
import re as _re

import pytest

from stelarstrike.plugins.sqli_extract import SQLiExtractor, ExtractionResult

S = SQLiExtractor._SENTINEL_START
E = SQLiExtractor._SENTINEL_END
LITERAL = SQLiExtractor._LITERAL_PROBE


def _wrap(value: str) -> str:
    return f'{{"username": "{S}{value}{E}", "token": "eyJ..."}}'


def _make_preconfigured_extractor(inject_responses: dict, db_type: str = "postgresql") -> SQLiExtractor:
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


# ── value extraction ─────────────────────────────────────────────────────────

def test_extract_value_finds_sentinel_in_json():
    ext = _make_preconfigured_extractor({})
    result = ext._extract_value(_wrap("PostgreSQL 13.23"))
    assert result == "PostgreSQL 13.23"


def test_extract_value_finds_sentinel_in_html():
    ext = _make_preconfigured_extractor({})
    html = f"<html><nav>Home Products</nav><p>{S}PostgreSQL 13.23{E}</p></html>"
    assert ext._extract_value(html) == "PostgreSQL 13.23"


def test_extract_value_empty_when_no_sentinel():
    ext = _make_preconfigured_extractor({})
    assert ext._extract_value("<html><body>Login failed.</body></html>") == ""


# ── baseline-diff detection: the actual bug fix ──────────────────────────────

@pytest.mark.asyncio
async def test_silent_app_detected_via_baseline_diff_not_error_text():
    """
    Simulates the real-world bug: an app that swallows EVERY SQL exception
    and re-renders the exact same page regardless of column-count
    correctness. The old error-text-based detection could never work here.
    Baseline-diff detection must still find the reflected column because a
    CORRECT column count changes the response (reflects STELRPROBE) while
    an INCORRECT one returns byte-identical content to the baseline.
    """
    BASELINE_PAGE = '{"username": "", "message": "Invalid credentials"}'
    CORRECT_COL_COUNT = 3
    CORRECT_POSITION = 1

    async def mock_inject(payload: str) -> str:
        if payload == "":
            return BASELINE_PAGE

        p = payload.lower()
        m = _re.search(r"union select (.+?)(?:--|#|;|$)", p)
        if not m:
            return BASELINE_PAGE  # no UNION at all -> looks like baseline
        cols = [c.strip() for c in m.group(1).split(",")]
        n = len(cols)

        # Silently swallow wrong column count -> identical to baseline, no error text
        if n != CORRECT_COL_COUNT:
            return BASELINE_PAGE

        # Correct column count: reflect literal probe if present at the right position
        for i, col in enumerate(cols):
            if LITERAL.lower() in col and i == CORRECT_POSITION:
                return f'{{"username": "{LITERAL}", "message": "ok"}}'
            if S.lower() in col and i == CORRECT_POSITION:
                return _wrap("extracted_value")

        # Correct column count but wrong position -> still "succeeds" but no reflection,
        # response differs slightly from baseline (no error) but doesn't contain probe
        return '{"username": "", "message": "ok, no reflection"}'

    ext = SQLiExtractor(
        inject_fn=mock_inject,
        db_type="postgresql",
        config={"enabled": True},
    )
    found = await ext._find_col_count_and_position(f"'{S}'||(version())||'{E}'", "-- -")
    assert found is True
    assert ext._col_count == CORRECT_COL_COUNT
    assert ext._reflected_col == CORRECT_POSITION


@pytest.mark.asyncio
async def test_completely_silent_app_with_no_diff_falls_through_to_ai():
    """If literally nothing differs from baseline ever, automated probing must
    give up and hand off to the AI agent (tested separately) rather than
    hang or false-positive on col_count=1."""
    BASELINE_PAGE = '{"message": "always the same"}'

    async def mock_inject(payload: str) -> str:
        return BASELINE_PAGE  # never differs, no matter what

    ai_calls = []

    async def _run():
        def fake_ai(prompt: str) -> str:
            ai_calls.append(prompt)
            return '{"payload": "", "col_count": null, "position": null, "reasoning": "give up"}'

        ext = SQLiExtractor(
            inject_fn=mock_inject,
            db_type="postgresql",
            config={"enabled": True},
            ai_client=fake_ai,
        )
        found = await ext._find_col_count_and_position(f"'{S}'||(version())||'{E}'", "-- -")
        return found, ext

    found, ext = await _run()
    assert found is False
    assert len(ai_calls) > 0, "AI agent loop should have been invoked"


# ── iterative AI agent loop ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ai_agent_loop_is_genuinely_iterative_not_one_shot():
    """
    The AI must be given multiple rounds, each seeing the prior attempt's
    result, until it succeeds or exhausts max_rounds. This test simulates
    an AI that gets it wrong twice before succeeding on round 3.
    """
    BASELINE = '{"message": "no"}'
    round_count = {"n": 0}

    async def mock_inject(payload: str) -> str:
        if payload == "":
            return BASELINE
        if "col_count_3_pos_1" in payload:
            return _wrap("found_it")
        return BASELINE

    def fake_ai(prompt: str) -> str:
        round_count["n"] += 1
        n = round_count["n"]
        if n == 1:
            return '{"payload": "col_count_2_pos_0_attempt", "col_count": 2, "position": 0, "prefix": "\'", "comment": "-- -", "reasoning": "try 2 cols"}'
        if n == 2:
            return '{"payload": "col_count_5_pos_3_attempt", "col_count": 5, "position": 3, "prefix": "\'", "comment": "-- -", "reasoning": "try 5 cols"}'
        return '{"payload": "col_count_3_pos_1", "col_count": 3, "position": 1, "prefix": "\'", "comment": "-- -", "reasoning": "try 3 cols pos 1"}'

    ext = SQLiExtractor(
        inject_fn=mock_inject,
        db_type="postgresql",
        config={"enabled": True},
        ai_client=fake_ai,
    )
    found = await ext._ai_agent_loop(f"'{S}'||(version())||'{E}'", BASELINE, max_rounds=6)

    assert found is True
    assert round_count["n"] == 3, f"expected exactly 3 AI rounds before success, got {round_count['n']}"
    assert ext._col_count == 3
    assert ext._reflected_col == 1


@pytest.mark.asyncio
async def test_ai_agent_loop_gives_up_after_max_rounds():
    async def mock_inject(payload: str) -> str:
        return '{"message": "never changes"}'

    call_count = {"n": 0}

    def fake_ai(prompt: str) -> str:
        call_count["n"] += 1
        return '{"payload": "some_attempt", "col_count": 4, "position": 0, "reasoning": "guess"}'

    ext = SQLiExtractor(
        inject_fn=mock_inject,
        db_type="postgresql",
        config={"enabled": True},
        ai_client=fake_ai,
    )
    found = await ext._ai_agent_loop(f"'{S}'||(version())||'{E}'", '{"message": "never changes"}', max_rounds=3)

    assert found is False
    assert call_count["n"] == 3, "should try exactly max_rounds times, no more no less"


@pytest.mark.asyncio
async def test_ai_call_failure_does_not_crash_extraction():
    """If the AI client raises (e.g. temperature rejected by model), the
    extractor must degrade gracefully, not propagate the exception."""
    async def mock_inject(payload: str) -> str:
        return '{"message": "baseline"}'

    def crashing_ai(prompt: str) -> str:
        raise Exception("litellm.BadRequestError: temperature does not support 0")

    ext = SQLiExtractor(
        inject_fn=mock_inject,
        db_type="postgresql",
        config={"enabled": True},
        ai_client=crashing_ai,
    )
    # Should not raise
    found = await ext._ai_agent_loop(f"'{S}'||(version())||'{E}'", '{"message": "baseline"}', max_rounds=2)
    assert found is False


# ── version / table / column extraction (cached-position path) ──────────────

@pytest.mark.asyncio
async def test_postgresql_version_extraction():
    ext = _make_preconfigured_extractor({"version()": _wrap("PostgreSQL 13.23 on x86_64")})
    version = await ext._get_version()
    assert "PostgreSQL" in version
    assert "13.23" in version


@pytest.mark.asyncio
async def test_table_discovery_parses_space_separated_names():
    ext = _make_preconfigured_extractor({"pg_tables": _wrap("users orders api_keys")})
    tables = await ext._get_tables()
    assert "users" in tables
    assert "api_keys" in tables


@pytest.mark.asyncio
async def test_column_discovery():
    ext = _make_preconfigured_extractor({
        "information_schema.columns": _wrap("id username email password"),
    })
    cols = await ext._get_columns("users")
    assert "username" in cols
    assert "password" in cols


# ── table ranking ─────────────────────────────────────────────────────────────

def test_high_value_table_ranking():
    ext = _make_preconfigured_extractor({})
    ext.result.tables = ["products", "users", "orders", "admin_tokens", "logs"]
    ranked = ext._rank_tables()
    assert ranked.index("users") < ranked.index("products")
    assert ranked.index("admin_tokens") < ranked.index("logs")


# ── markdown table rendering ("Big Pickle style") ────────────────────────────

def test_markdown_table_rendering():
    result = ExtractionResult(
        db_version="PostgreSQL 13.23",
        db_type="postgresql",
        tables=["users"],
        columns={"users": ["id", "username", "password"]},
        data={"users": [
            {"id": "1", "username": "admin", "password": "hunter2"},
            {"id": "2", "username": "bob", "password": "hunter3"},
        ]},
    )
    md = result.to_markdown_tables()
    assert "| id | username | password |" in md
    assert "| 1 | admin | hunter2 |" in md
    assert "| 2 | bob | hunter3 |" in md
    assert "PostgreSQL 13.23" in md


def test_markdown_table_handles_no_data():
    result = ExtractionResult()
    md = result.to_markdown_tables()
    assert "No data extracted" in md


def test_markdown_table_escapes_pipe_characters():
    result = ExtractionResult(
        db_version="PG",
        db_type="postgresql",
        tables=["t"],
        columns={"t": ["col"]},
        data={"t": [{"col": "value|with|pipes"}]},
    )
    md = result.to_markdown_tables()
    assert "\\|" in md


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
