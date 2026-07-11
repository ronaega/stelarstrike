import asyncio

from unittest.mock import AsyncMock

import pytest

from stelarstrike.core.target import Target
from stelarstrike.plugins.base import PluginContext
from stelarstrike.plugins.sqli import SQLiPlugin


class _FakeResp:
    def __init__(self, text: str, status_code: int = 200, headers: dict | None = None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


LOGIN_PAGE = """<html><body>
<form method="post" action="/login">
<input name="username">
<input name="password" type="password">
<input type="submit">
</form>
</body></html>"""


def _make_ctx(client: AsyncMock, url: str, allow_active: bool = True, options: dict | None = None) -> PluginContext:
    return PluginContext(
        target=Target(url=url),
        http_client=client,
        options=options or {"techniques": ["error-based", "boolean-blind"]},
        allow_active_payloads=allow_active,
        semaphore=asyncio.Semaphore(10),
    )


@pytest.mark.asyncio
async def test_sqli_detects_login_form_auth_bypass():
    async def fake_get(url, *a, **kw):
        return _FakeResp(LOGIN_PAGE)

    async def fake_post(url, data=None, json=None, *a, **kw):
        body = data if data is not None else json
        username = body.get("username", "")
        if username in ("' OR 1=1-- -", "' OR '1'='1'-- -"):
            return _FakeResp('Welcome back! <a href="/logout">Logout</a>', 200)
        if username == "stelarstrike_nonexistent_user":
            return _FakeResp("Invalid username or password", 200)
        if "'" in username:
            return _FakeResp("you have an error in your sql syntax near line 1", 500)
        return _FakeResp("Invalid username or password", 200)

    client = AsyncMock()
    client.get.side_effect = fake_get
    client.post.side_effect = fake_post

    plugin = SQLiPlugin(_make_ctx(client, "http://target.test/login"))
    findings = await plugin.run()

    titles = [f.title for f in findings]
    assert any("authentication bypass" in t.lower() for t in titles)
    bypass = next(f for f in findings if "authentication bypass" in f.title.lower())
    assert bypass.severity == "critical"
    assert bypass.confidence == "high"


@pytest.mark.asyncio
async def test_sqli_baseline_guard_prevents_false_positive_on_noisy_app():
    async def fake_get(url, *a, **kw):
        # This app always mentions "database error" in its footer text,
        # regardless of input — a scanner without a baseline check would
        # false-positive on every request.
        return _FakeResp("Welcome. Note: database error logging is enabled for this demo app.")

    client = AsyncMock()
    client.get.side_effect = fake_get

    plugin = SQLiPlugin(
        _make_ctx(client, "http://target.test/?id=1", allow_active=False, options={"techniques": ["error-based"]})
    )
    findings = await plugin.run()

    assert findings == []


@pytest.mark.asyncio
async def test_sqli_tests_post_form_as_both_form_and_json_body():
    seen_json_calls = []
    seen_form_calls = []

    async def fake_get(url, *a, **kw):
        return _FakeResp('<html><body><form method="post" action="/search">'
                          '<input name="q"></form></body></html>')

    async def fake_post(url, data=None, json=None, *a, **kw):
        if json is not None:
            seen_json_calls.append(json)
        if data is not None:
            seen_form_calls.append(data)
        return _FakeResp("no results")

    client = AsyncMock()
    client.get.side_effect = fake_get
    client.post.side_effect = fake_post

    plugin = SQLiPlugin(
        _make_ctx(client, "http://target.test/", allow_active=False, options={"techniques": ["error-based"]})
    )
    await plugin.run()

    assert len(seen_json_calls) > 0, "expected at least one JSON-body POST attempt"
    assert len(seen_form_calls) > 0, "expected at least one form-encoded POST attempt"
