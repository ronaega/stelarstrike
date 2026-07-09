"""Shared helpers for parsing pages/forms/params, used by multiple plugins."""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from bs4 import BeautifulSoup


def get_query_params(url: str) -> dict[str, str]:
    """Return the first value of every query param on a URL."""
    parsed = urlparse(url)
    return {k: v[0] for k, v in parse_qs(parsed.query).items()}


def build_url_with_params(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=urlencode(params)))


def extract_forms(html: str) -> list[dict]:
    """Extract <form> elements as a list of dicts: action, method, inputs."""
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue
            inputs.append({
                "name": name,
                "type": tag.get("type", "text"),
                "value": tag.get("value", ""),
            })
        forms.append({
            "action": form.get("action", ""),
            "method": form.get("method", "get").lower(),
            "inputs": inputs,
        })
    return forms
