"""
Alternative Schema Loader.

Schemas are generic PATTERN files (Flask+PostgreSQL, Django REST, etc.) —
they are NOT named after or tied to specific targets.

When a target matches a pattern, the orchestrator:
  1. Adds the pattern's probe_endpoints to the scan queue (alongside discovery)
  2. Passes sqli.try_positions_first to guide extraction (not bypass it)
  3. Notes extra_checks for the scan report

Fingerprinting uses OR logic — a target matches if ANY ONE fingerprint fires.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

from stelarstrike.utils.logger import get_logger

log = get_logger(__name__)

_SCHEMAS_DIR = Path(__file__).parent.parent.parent / "schemas"


@dataclass
class SchemaMatch:
    name: str
    description: str
    probe_endpoints: list[dict[str, Any]] = field(default_factory=list)
    sqli_hints: dict[str, Any] = field(default_factory=dict)
    extra_checks: list[dict[str, Any]] = field(default_factory=list)
    matched_fingerprint: str = ""

    def get_sqli_hints(self) -> dict[str, Any]:
        return self.sqli_hints

    def summary(self) -> str:
        hints = self.sqli_hints
        lines = [
            f"Pattern matched: {self.name}",
            f"  Fingerprint: {self.matched_fingerprint}",
            f"  Probe endpoints: {len(self.probe_endpoints)}",
        ]
        if hints.get("try_positions_first"):
            lines.append(f"  SQLi try positions first: {hints['try_positions_first']}")
        if hints.get("likely_db"):
            lines.append(f"  Likely DB: {hints['likely_db']}")
        return "\n".join(lines)


def _load_all_schemas() -> list[dict[str, Any]]:
    schemas = []
    if not _SCHEMAS_DIR.exists():
        return schemas
    for path in sorted(_SCHEMAS_DIR.glob("*.yaml")):
        if path.name in ("README.md", "example.yaml"):
            continue
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data and isinstance(data, dict) and data.get("fingerprints"):
                data["_source_file"] = path.name
                schemas.append(data)
        except Exception as exc:  # noqa: BLE001
            log.warning(f"schema: could not load '{path.name}': {exc}")
    return schemas


def _check_fingerprint(fp: dict, body: str, headers: dict) -> bool:
    """Check one fingerprint — all fields within it must match (AND within one fp)."""
    if "response_contains" in fp:
        if fp["response_contains"].lower() not in body.lower():
            return False
    if "header_contains" in fp:
        needle = fp["header_contains"].lower()
        if not any(needle in str(v).lower() for v in headers.values()):
            return False
    return True


def _fingerprint_matches(fingerprints: list[dict], body: str, headers: dict) -> str | None:
    """
    OR logic — return the matched fingerprint description if ANY matches, else None.
    """
    for fp in fingerprints:
        if _check_fingerprint(fp, body, headers):
            return str(next(iter(fp.values())))
    return None


async def match_schema(
    target_url: str,
    http_client: httpx.AsyncClient,
) -> SchemaMatch | None:
    """
    Fetch the target root URL and check against all loaded schemas.
    Returns the first matching SchemaMatch, or None if no pattern matches.
    """
    schemas = _load_all_schemas()
    if not schemas:
        log.debug("schema: no schema files found in schemas/")
        return None

    try:
        resp = await asyncio.wait_for(http_client.get(target_url), timeout=10)
        body = resp.text
        headers = dict(resp.headers)
    except Exception as exc:  # noqa: BLE001
        log.debug(f"schema: fingerprint fetch failed for '{target_url}': {exc}")
        return None

    for schema_data in schemas:
        fingerprints = schema_data.get("fingerprints", [])
        matched = _fingerprint_matches(fingerprints, body, headers)
        if matched:
            log.info(
                f"schema: pattern '{schema_data.get('name')}' matched "
                f"(fingerprint: '{matched}')"
            )
            return SchemaMatch(
                name=schema_data.get("name", "Unknown Pattern"),
                description=schema_data.get("description", ""),
                probe_endpoints=schema_data.get("probe_endpoints", []),
                sqli_hints=schema_data.get("sqli", {}),
                extra_checks=schema_data.get("extra_checks", []),
                matched_fingerprint=matched,
            )

    log.debug(f"schema: no pattern match for '{target_url}' ({len(schemas)} schema(s) checked)")
    return None
