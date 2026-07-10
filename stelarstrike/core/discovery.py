"""
Discovery: builds a list of candidate URLs to scan when the user gives
a bare target (no query string) — so plugins that rely on parameters
(sqli, nosqli, idor, ssrf) have something to test without the user
manually guessing a parameter name.

Strategy (kept intentionally simple/fast — this is not a full spider):
  1. Always include the user-supplied target as-is.
  2. Fetch it, extract same-origin <a href> links and <form> actions.
  3. For links that already carry a query string, keep them directly.
  4. For discovered pages without a query string (e.g. /search, /login),
     fetch each (bounded by max_depth/max_urls) and turn any GET form
     found there into a candidate URL using its input names.
  5. If nothing parametrized turns up anywhere, fall back to appending
     a small set of common parameter names to the original target
     ("synthetic" candidates) so injection-style plugins aren't
     completely blind. These are clearly logged as guessed.

Every candidate is re-checked against engagement scope before being
returned — discovery can only ever narrow within the scope the user
already approved, never widen it.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from stelarstrike.core.target import Target, ScopeError, enforce_scope
from stelarstrike.utils.http_client import build_url_with_params, extract_forms, get_query_params
from stelarstrike.utils.logger import get_logger

log = get_logger(__name__)


async def discover_targets(
    base_url: str,
    http_client: httpx.AsyncClient,
    scope: list[str],
    out_of_scope: list[str],
    max_urls: int = 10,
    max_depth: int = 1,
    synthetic_params: list[str] | None = None,
) -> list[str]:
    synthetic_params = synthetic_params or ["id", "page", "category", "search", "q", "user_id"]
    origin = urlparse(base_url)
    candidates: set[str] = {base_url}

    try:
        resp = await http_client.get(base_url)
        html = resp.text
    except Exception as exc:  # noqa: BLE001
        log.warning(f"Discovery: could not fetch '{base_url}' ({exc}); scanning only the given URL.")
        return [base_url]

    to_crawl: list[str] = []
    soup = BeautifulSoup(html, "html.parser")

    for a in soup.find_all("a", href=True):
        link = urljoin(base_url, a["href"])
        parsed = urljoin(base_url, a["href"])
        link_parsed = urlparse(parsed)
        if link_parsed.netloc != origin.netloc:
            continue  # stay same-origin — this is a scanner, not a spider
        if link_parsed.scheme not in ("http", "https"):
            continue
        if get_query_params(link):
            candidates.add(link)
        elif len(to_crawl) < max_depth * max_urls:
            to_crawl.append(link.split("#")[0])

    for form in extract_forms(html):
        if form["method"] == "get" and form["inputs"]:
            params = {i["name"]: i.get("value") or "1" for i in form["inputs"]}
            action = urljoin(base_url, form["action"]) if form["action"] else base_url
            candidates.add(build_url_with_params(action, params))

    for link in to_crawl[: max_urls]:
        if len(candidates) >= max_urls:
            break
        try:
            page_resp = await http_client.get(link)
        except Exception:
            continue
        for form in extract_forms(page_resp.text):
            if form["method"] == "get" and form["inputs"]:
                params = {i["name"]: i.get("value") or "1" for i in form["inputs"]}
                action = urljoin(link, form["action"]) if form["action"] else link
                candidates.add(build_url_with_params(action, params))

    if len(candidates) == 1 and not get_query_params(base_url):
        log.info("Discovery: no parametrized URLs found; guessing common parameter names.")
        for name in synthetic_params:
            candidates.add(build_url_with_params(base_url, {name: "1"}))

    in_scope: list[str] = []
    for url in candidates:
        try:
            enforce_scope(Target(url=url), scope=scope, out_of_scope=out_of_scope)
            in_scope.append(url)
        except ScopeError:
            log.info(f"Discovery: skipping out-of-scope discovered URL '{url}'")

    if base_url not in in_scope:
        in_scope.insert(0, base_url)

    return in_scope[:max_urls]
