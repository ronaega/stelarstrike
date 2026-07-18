from unittest.mock import AsyncMock

import pytest

from assets.core.discovery import discover_targets


class _FakeResp:
    def __init__(self, text: str):
        self.text = text


def _client_returning(pages: dict[str, str], default: str = "") -> AsyncMock:
    async def fake_get(url, *args, **kwargs):
        return _FakeResp(pages.get(url, default))

    client = AsyncMock()
    client.get.side_effect = fake_get
    return client


@pytest.mark.asyncio
async def test_discovery_finds_linked_and_form_params():
    pages = {
        "http://target.test/": (
            '<html><body><a href="/product?id=1">Product</a>'
            '<a href="/search">Search</a></body></html>'
        ),
        "http://target.test/search": (
            '<html><body><form method="get" action="/search">'
            '<input name="q"></form></body></html>'
        ),
    }
    urls = await discover_targets(
        base_url="http://target.test/",
        http_client=_client_returning(pages),
        scope=["http://target.test/*", "http://target.test"],
        out_of_scope=[],
    )
    assert "http://target.test/product?id=1" in urls
    assert any(u.startswith("http://target.test/search?q=") for u in urls)
    assert "http://target.test/" in urls


@pytest.mark.asyncio
async def test_discovery_falls_back_to_synthetic_params_when_nothing_found():
    client = _client_returning({}, default="<html><body>nothing here</body></html>")
    urls = await discover_targets(
        base_url="http://target.test/",
        http_client=client,
        scope=["http://target.test/*", "http://target.test"],
        out_of_scope=[],
        synthetic_params=["id", "page"],
    )
    assert any(u.endswith("?id=1") for u in urls)
    assert any(u.endswith("?page=1") for u in urls)


@pytest.mark.asyncio
async def test_discovery_never_leaks_out_of_scope_or_cross_origin_urls():
    page = (
        '<html><body><a href="/in-scope?id=1">ok</a>'
        '<a href="http://evil.test/steal?id=1">bad</a></body></html>'
    )
    client = _client_returning({}, default=page)
    urls = await discover_targets(
        base_url="http://target.test/",
        http_client=client,
        scope=["http://target.test/*", "http://target.test"],
        out_of_scope=[],
    )
    assert not any("evil.test" in u for u in urls)
