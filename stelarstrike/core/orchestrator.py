"""
Orchestrator: the core loop that ties everything together.

Responsibilities:
  1. Validate the target against engagement scope (fail closed).
  2. Instantiate every enabled plugin.
  3. Run plugins concurrently (bounded by http.max_concurrency).
  4. Collect Findings into a ReportBuilder.
  5. Optionally hand findings to the AI layer for triage + narrative.
  6. Write markdown/json reports to disk.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from stelarstrike.core.ai_client import AIClient
from stelarstrike.core.config import PluginConfig, Settings
from stelarstrike.core.discovery import discover_targets
from stelarstrike.core.report import Finding, ReportBuilder
from stelarstrike.core.schema_loader import match_schema
from stelarstrike.core.target import Target, enforce_scope
from stelarstrike.plugins import PLUGIN_REGISTRY
from stelarstrike.plugins.base import PluginContext
from stelarstrike.utils.logger import get_logger

log = get_logger(__name__)


class Orchestrator:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.ai_client = AIClient(settings.ai)
        self.matched_schema = None  # set after schema check; readable by tests/CLI

    async def run(self, target_url: str, plugin_filter: set[str] | None = None) -> ReportBuilder:
        target = Target(url=target_url)
        enforce_scope(
            target,
            scope=self.settings.engagement.scope,
            out_of_scope=self.settings.engagement.out_of_scope,
        )

        report = ReportBuilder(
            engagement_name=self.settings.engagement.name,
            report_dir=self.settings.report_dir,
        )

        limits = httpx.Limits(max_connections=self.settings.http.max_concurrency)
        headers = {"User-Agent": self.settings.http.user_agent, **self.settings.http.extra_headers}

        async with httpx.AsyncClient(
            timeout=self.settings.http.timeout_seconds,
            follow_redirects=self.settings.http.follow_redirects,
            verify=self.settings.http.verify_tls,
            limits=limits,
            headers=headers,
        ) as http_client:
            semaphore = asyncio.Semaphore(self.settings.http.max_concurrency)

            # Schema matching — check against known target patterns before discovery.
            # A match skips column-count enumeration and goes straight to known parameters.
            self.matched_schema = await match_schema(target_url, http_client)
            if self.matched_schema:
                log.info(self.matched_schema.summary())

            target_urls = [target_url]
            if self.settings.discovery.enabled:
                # If schema provides known endpoints, also scan those directly.
                if self.matched_schema:
                    base_host = target_url.rstrip("/")
                    for ep in self.matched_schema.endpoints:
                        if not ep.get("auth_required", False) and ep.get("method") in ("GET", "POST"):
                            ep_url = base_host + ep["path"]
                            if ep_url not in target_urls:
                                target_urls.append(ep_url)
                    log.info(f"Schema: added {len(target_urls) - 1} known endpoint(s) to scan queue")
                else:
                    target_urls = await discover_targets(
                        base_url=target_url,
                        http_client=http_client,
                        scope=self.settings.engagement.scope,
                        out_of_scope=self.settings.engagement.out_of_scope,
                        max_urls=self.settings.discovery.max_urls,
                        max_depth=self.settings.discovery.max_depth,
                        synthetic_params=self.settings.discovery.synthetic_params,
                    )
                    log.info(f"Discovery: scanning {len(target_urls)} URL(s): {target_urls}")

            # Build schema hints for plugins that support them (e.g. sqli)
            schema_hints: dict[str, Any] = {}
            if self.matched_schema:
                sqli_hints = self.matched_schema.get_sqli_hints()
                if sqli_hints:
                    schema_hints["sqli_hints"] = sqli_hints

            tasks = []
            for url in target_urls:
                url_target = Target(url=url)
                for plugin_id, plugin_cls in PLUGIN_REGISTRY.items():
                    if plugin_filter is not None:
                        if plugin_id not in plugin_filter:
                            continue
                        plugin_cfg = self.settings.plugins.get(plugin_id) or PluginConfig()
                    else:
                        plugin_cfg = self.settings.plugins.get(plugin_id)
                        if plugin_cfg is None or not plugin_cfg.enabled:
                            continue

                    # Merge schema hints into plugin options (schema wins for known parameters)
                    merged_options = {**plugin_cfg.options}
                    if plugin_id == "sqli" and "sqli_hints" in schema_hints:
                        merged_options["schema_hints"] = schema_hints["sqli_hints"]

                    ctx = PluginContext(
                        target=url_target,
                        http_client=http_client,
                        options=merged_options,
                        allow_active_payloads=self.settings.engagement.allow_active_payloads,
                        semaphore=semaphore,
                    )
                    tasks.append(self._run_plugin(plugin_id, plugin_cls, ctx, report))

            if not tasks:
                log.info("No enabled plugins to run — check `plugins:` in config.yaml")

            if tasks:
                await asyncio.gather(*tasks)

        if self.ai_client.config.enabled:
            findings_dicts = report.as_dicts()
            triaged = self.ai_client.triage_findings(findings_dicts)
            self._apply_triage(report, triaged)
            report.narrative = self.ai_client.draft_report_narrative(
                self.settings.engagement.name, report.as_dicts()
            )

        return report

    @staticmethod
    async def _run_plugin(plugin_id: str, plugin_cls: Any, ctx: PluginContext, report: ReportBuilder) -> None:
        log.info(f"[run]  plugin '{plugin_id}' -> {ctx.target.url}")
        try:
            plugin = plugin_cls(ctx)
            findings: list[Finding] = await plugin.run()
            for f in findings:
                report.add(f)
            log.info(f"[done] plugin '{plugin_id}': {len(findings)} finding(s)")
        except Exception as exc:  # noqa: BLE001 — one plugin failing must not kill the scan
            log.error(f"[fail] plugin '{plugin_id}' raised: {exc}")

    @staticmethod
    def _apply_triage(report: ReportBuilder, triaged: list[dict[str, Any]]) -> None:
        """Merge AI-added priority/exploitability_note fields back onto Findings."""
        if len(triaged) != len(report.findings):
            return
        for finding, triaged_item in zip(report.findings, triaged):
            finding.extra["priority"] = triaged_item.get("priority")
            finding.extra["exploitability_note"] = triaged_item.get("exploitability_note")
