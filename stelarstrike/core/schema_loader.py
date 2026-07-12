"""
Alternative Schema Loader.

Loads YAML schema files from the `schemas/` directory, fingerprints
the target against each one, and — on a match — provides known
injection parameters to the scan so it can skip slow discovery and
column-count enumeration.

Benefit 1 — Speed: skips 20–100+ HTTP requests on a schema match.
Benefit 2 — AI tokens: skip triage call when findings are already
  documented in the schema's `additional_findings`.
Benefit 3 — Accuracy: uses confirmed column count + reflected position
  directly, so extraction works first try instead of probing.

Usage in orchestrator:

    schema = await match_schema(target_url, http_client)
    if schema:
        # Feed known sqli parameters directly to SQLiExtractor
        sqli_hints = schema.get_sqli_hints("login_username_sqli")
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
    source: str
    stack: dict[str, str] = field(default_factory=dict)
    injections: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    additional_findings: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def get_sqli_hints(self, injection_id: str | None = None) -> dict[str, Any] | None:
        """
        Return the sqli sub-dict for the specified injection id, or the first
        confirmed sqli injection if no id is given.

        Callers can use this to pre-configure SQLiExtractor:
            hints = schema.get_sqli_hints()
            if hints:
                extractor._col_count = hints["col_count"]
                extractor._reflected_col = hints["reflected_col"]
                extractor._inject_prefix = hints.get("inject_prefix", "'")
                extractor.db_type = hints["db_type"]
        """
        for inj in self.injections:
            if injection_id and inj.get("id") != injection_id:
                continue
            if inj.get("injection_type") == "sqli" and inj.get("sqli"):
                return inj["sqli"]
        return None

    def summary(self) -> str:
        lines = [
            f"Schema matched: {self.name}",
            f"  Source: {self.source}",
            f"  Stack: {', '.join(f'{k}={v}' for k, v in self.stack.items())}",
        ]
        for inj in self.injections:
            hints = inj.get("sqli", {})
            lines.append(
                f"  Known injection: {inj.get('endpoint')} "
                f"[{inj.get('method')}:{inj.get('body_type')}] "
                f"field={inj.get('field')} "
                f"col_count={hints.get('col_count')} "
                f"reflected_col={hints.get('reflected_col')}"
            )
        return "\n".join(lines)


def _load_all_schemas() -> list[dict[str, Any]]:
    schemas = []
    if not _SCHEMAS_DIR.exists():
        return schemas
    for path in sorted(_SCHEMAS_DIR.glob("*.yaml")):
        if path.name == "example.yaml":
            continue
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data and isinstance(data, dict):
                data["_source_file"] = path.name
                schemas.append(data)
        except Exception as exc:  # noqa: BLE001
            log.warning(f"schema: could not load '{path.name}': {exc}")
    return schemas


def _fingerprint_matches(fingerprints: list[dict], response_body: str, response_headers: dict) -> bool:
    """Return True only if ALL fingerprints in the list are satisfied."""
    if not fingerprints:
        return False
    for fp in fingerprints:
        if "response_contains" in fp:
            if fp["response_contains"].lower() not in response_body.lower():
                return False
        if "header_contains" in fp:
            needle = fp["header_contains"].lower()
            if not any(needle in v.lower() for v in response_headers.values()):
                return False
        if "status_code" in fp:
            pass  # status_code is checked at call site
    return True


async def match_schema(
    target_url: str,
    http_client: httpx.AsyncClient,
) -> SchemaMatch | None:
    """
    Fetch the target root URL and compare against all loaded schemas.
    Returns the first matching SchemaMatch, or None if no match.
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
        if not fingerprints:
            continue
        if _fingerprint_matches(fingerprints, body, headers):
            log.info(
                f"schema: matched '{schema_data.get('name', schema_data['_source_file'])}' "
                f"for target '{target_url}'"
            )
            return SchemaMatch(
                name=schema_data.get("name", ""),
                description=schema_data.get("description", ""),
                source=schema_data.get("source", ""),
                stack=schema_data.get("stack", {}),
                injections=schema_data.get("injections", []),
                endpoints=schema_data.get("endpoints", []),
                additional_findings=schema_data.get("additional_findings", []),
                raw=schema_data,
            )

    log.debug(f"schema: no match for '{target_url}' across {len(schemas)} schema(s)")
    return None
