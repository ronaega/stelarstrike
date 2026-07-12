# PRD — StelarStrike

**Status:** v1.0 (initial release)
**Owner:** Rona
**Last updated:** 2026-07-09

> This document is written to be portable: paste it into any AI coding tool (Claude, ChatGPT, Codex, Cursor, etc.) along with the repo, and it should have everything needed to keep building StelarStrike consistently with the original design intent.

---

## 1. Problem Statement

Penetration testers and security researchers routinely re-run the same handful of vulnerability checks (SQLi, XSS, SSRF, CSRF, IDOR, JWT issues, etc.) against every new target, using a scattered set of single-purpose tools and scripts. This is slow, inconsistent between engagements, and produces findings in incompatible formats that are tedious to compile into a report.

**StelarStrike** solves this by providing a single, extensible **orchestration framework**: one CLI command runs a configurable set of vulnerability plugins concurrently against a target, normalizes every result into one data model, optionally uses an LLM to triage and narrate the findings, and emits a ready-to-share report.

## 2. Goals

- G1 — Ship a working, testable v1.0 covering 8 core web vulnerability classes.
- G2 — Make every piece of behavior (plugins, AI provider/model, scope, active-payload policy, HTTP behavior) configurable without touching code.
- G3 — Keep the AI layer fully optional; the tool must be 100% usable with `ai.enabled: false`.
- G4 — Make adding a new vulnerability class a "one new file + one registry line" operation.
- G5 — Default to safe/passive behavior; anything that could affect a production system (timing attacks, forged tokens, real file uploads) requires an explicit opt-in flag.
- G6 — Ship with CI (lint + test + Docker build) from day one so contributions stay reliable.

### Non-goals (v1.0)

- NG1 — Not a network/infra scanner (no port scanning, no OS-level checks).
- NG2 — Not an authenticated-session manager — v1.0 assumes the target URL/cookies/headers you pass in are already sufficient (no login-flow automation yet).
- NG3 — Not a full spider/fuzzer — discovery (§5.5) is a lightweight, one-level-deep same-origin crawl to find parametrized URLs, not exhaustive wordlist-based directory/parameter brute-forcing (candidate for a future deeper-crawl mode).
- NG4 — No built-in OOB collaborator server — SSRF OOB checks rely on a user-supplied collaborator URL.
- NG5 — No GUI/dashboard — CLI + Markdown/JSON reports only.
- NG6 — No automated data extraction, even where a vulnerability is confirmed exploitable (e.g. `sqli`'s UNION-confirm stops at column count; it never runs `version()`/`information_schema` queries or dumps rows) and no automated second-order SQLi (register-then-trigger chains). Both are legitimate follow-up techniques but are meaningfully more invasive/stateful than every other check in this tool and are left to manual, human-supervised follow-up.

## 3. Target Users

- Independent penetration testers / bug bounty hunters who want one CLI to run baseline checks before manual testing.
- Security students/researchers building a portfolio project (this project itself is partly intended as a learning/portfolio artifact).
- Small AppSec teams wanting a lightweight, self-hosted first-pass scanner ahead of a full commercial scanner or manual review.

## 4. Core Concepts / Data Model

### 4.1 `Target`
A single URL under test. Scope-checked before any plugin runs.

### 4.2 `Finding`
The universal output unit, produced by every plugin:

```python
@dataclass
class Finding:
    plugin: str            # plugin id, e.g. "sqli"
    title: str
    severity: str           # critical | high | medium | low | informational
    url: str
    parameter: str | None
    evidence: str | None
    description: str
    remediation: str
    confidence: str          # low | medium | high | confirmed
    cwe: str | None
    extra: dict[str, Any]    # AI-added fields land here (priority, exploitability_note, ...)
```

### 4.3 `VulnerabilityPlugin` (ABC)
Every vuln check subclasses this. Contract:
- Set class attributes `id`, `name`, `default_severity`.
- Implement `async def run(self) -> list[Finding]`.
- Must not raise on expected failure modes (network errors, unexpected response shapes) — the orchestrator treats an uncaught exception as a hard plugin failure and logs it, but a single plugin crashing must never abort the whole scan.
- Gate any payload that could reasonably affect target state or be considered "active exploitation" behind `self.ctx.allow_active_payloads`.

### 4.4 `PLUGIN_REGISTRY`
`stelarstrike/plugins/__init__.py` — a single `dict[str, type[VulnerabilityPlugin]]`. This is the **only** place the orchestrator/CLI look to discover plugins. Anything not in this dict does not exist to the rest of the system.

### 4.5 `Settings`
Loaded from `.env` (via `python-dotenv`) + `config/config.yaml` (via `pyyaml`, with `${VAR:-default}` interpolation against environment variables). Typed with Pydantic. Structure mirrors `config/config.example.yaml` — see README §Configuration for the authoritative field list.

## 5. Functional Requirements — v1.0 Plugins

Each plugin below lists: detection strategy, passive vs. active split, config keys, severity defaults, and CWE mapping. This table is the contract for what "done" means for each plugin; treat any change here as an intentional scope change worth a PRD update.

| # | Plugin ID | Detection strategy (passive) | Detection strategy (active, `allow_active_payloads: true`) | Severity | CWE |
|---|---|---|---|---|---|
| 1 | `sqli` | Error-based (multi-DBMS signatures: MySQL/PostgreSQL/MSSQL/SQLite/Oracle + framework debug-page leaks), baseline-checked to filter false positives. Boolean-blind: dual-TRUE-payload verified, dynamic-content-stripped comparison. Tests query params AND every form field, POST as both form-encoded and JSON body. Login-form auth-bypass detection (password-field heuristic). | Time-blind: MySQL/PostgreSQL/MSSQL delay payloads. UNION column-count confirmation (stops at confirmation, never extracts data) after error-based confirms injectability. | high (critical for confirmed auth-bypass or UNION-exploitable) | CWE-89 |
| 2 | `nosqli` | Send `$ne`/operator payload as JSON body value, compare status/length against baseline; match Mongo/BSON error signatures. | (same checks; no separate active-only path in v1.0) | high | CWE-943 |
| 3 | `xss` | Inject a unique marker with HTML metacharacters into query params and form fields, check for unescaped reflection. | Full `<script>` payload round-trip confirmation. | medium (high if confirmed) | CWE-79 |
| 4 | `ssrf` | Flag parameters by name/value heuristics (url, redirect, webhook, already-a-URL, ...). | Send out-of-band probe to a user-configured collaborator URL. | high (low/informational for heuristic-only) | CWE-918 |
| 5 | `csrf` | Parse forms, flag state-changing (`POST`) forms missing a CSRF token field; check `SameSite` cookie attribute as partial mitigation. | — (no active-only path; this class is inherently passive) | medium (high if no SameSite either, low if SameSite present) | CWE-352 |
| 6 | `file_upload` | Locate upload forms. | Upload inert probe files with dangerous extensions (`.php`, `.jsp`, ...), check acceptance + web-reachability of the stored file. | high (critical if reachability confirmed) | CWE-434 |
| 7 | `idor` | Match parameter names against identifier hints; classify integer vs. UUID identifiers. | Request a neighboring integer ID with the same session, compare response. | high (informational for UUID-only heuristic flag) | CWE-639 |
| 8 | `jwt` | Locate JWT in Authorization header/cookies. Decode (unverified) and check `kid` header for injection patterns; brute-force HS256 signature against a small common-secret wordlist. | `alg:none` forgery test; expired-token-reuse test (re-signed with a probe key). | high (critical if `alg:none` or weak-secret confirmed) | CWE-347 / CWE-798 / CWE-613 |

### 5.1 Orchestration requirements

- OR1 — Plugins run concurrently via `asyncio.gather`, bounded by `http.max_concurrency` (shared `asyncio.Semaphore`).
- OR2 — Scope is enforced once on the user-supplied target, before any plugin or discovery crawl runs (`core/target.py::enforce_scope`), and raises `ScopeError` which the CLI surfaces as a clean error + exit code 1 (never a stack trace).
- OR3 — A plugin raising an unhandled exception is caught at the orchestrator level, logged, and excluded from the report — it must not abort other plugins.
- OR4 — All plugins share one `httpx.AsyncClient` instance per scan (connection pooling, consistent headers/cookies/timeout).
- OR5 — When discovery is enabled, every enabled plugin runs once per discovered URL (not just the user-supplied one); findings from all URLs are aggregated into a single report.

### 5.5 Auto-discovery requirements

- DI1 — If `discovery.enabled` is true (default), `core/discovery.py::discover_targets` runs once per scan, before plugins, against the user-supplied target.
- DI2 — Discovery fetches the base URL, extracts same-origin `<a href>` links and `<form>` elements. Links carrying a query string are kept directly as candidates; GET forms are converted into a candidate URL using their input names (dummy value `"1"` unless the form specifies a default).
- DI3 — Discovery follows same-origin links one level deep (bounded by `discovery.max_depth` and `discovery.max_urls`) to find forms on pages like `/search` or `/login` that aren't linked with a query string themselves.
- DI4 — If, after crawling, zero parametrized URLs are found anywhere (including the original target), discovery falls back to appending each name in `discovery.synthetic_params` to the original URL as a guessed candidate — this keeps injection-style plugins (`sqli`, `nosqli`, `idor`) from being completely blind on a single-page target, at the cost of some guaranteed-empty synthetic checks.
- DI5 — **Every** candidate URL (crawled or synthetic) is re-validated against `engagement.scope` / `engagement.out_of_scope` before being returned. Discovery must never cause a scan to touch a URL that wouldn't have passed scope enforcement if the user had typed it manually. Cross-origin links are dropped before the scope check even runs (discovery never leaves the target's origin).
- DI6 — The original user-supplied URL is always included in the final candidate list, even if it isn't independently "discoverable" (e.g. it's always in the returned list at position 0 barring a scope conflict).
- DI7 — Discovery failures (target unreachable, parse errors) degrade gracefully to `[base_url]` — a broken crawl must never abort the scan.

### 5.2 AI layer requirements

- AI1 — `AIClient` wraps [LiteLLM](https://docs.litellm.ai/) so `ai.provider` accepts any LiteLLM model string (`anthropic/...`, `openai/...`, `azure/...`, `ollama/...`).
- AI2 — Three independently toggleable roles: `triage`, `report_writer`, `payload_advisor` (the latter unused by any plugin in v1.0 — reserved for v1.x active-payload plugins).
- AI3 — Every AI call must have a deterministic fallback (see `AIClient._fallback_narrative`, and `Orchestrator._apply_triage` no-ops if the AI response shape doesn't match). AI failures/timeouts must never crash a scan — log and continue.
- AI4 — AI triage must not fabricate findings — it only re-ranks/annotates the exact list of `Finding`s the plugins produced (`AIClient.triage_findings` sends the findings and expects the *same count* back with added fields; mismatched counts are ignored).

### 5.3 Reporting requirements

- RP1 — `ReportBuilder` emits both Markdown (human-readable) and JSON (machine-readable) from the same underlying `Finding` list.
- RP2 — Findings are sorted by severity (`critical > high > medium > low > informational`) in both the CLI summary table and the Markdown report.
- RP3 — Report filenames are `<slugified-engagement-name>-<UTC timestamp>.{md,json}`, written to `project.report_dir` (default `reports/`).

### 5.4 CLI requirements

- CLI1 — `stelarstrike scan <target> [--config PATH] [--formats markdown,json] [--plugins id1,id2] [--verbose]` — run a scan. `--plugins` overrides config.yaml's per-plugin `enabled` flags for that single run (does not persist/write back to config); omitted means "whatever config.yaml has enabled." `--verbose` forces DEBUG-level logging so every payload/response a plugin tries is visible — the primary tool for diagnosing an empty-findings scan.
- CLI2 — `stelarstrike plugins` — list all registered plugins (id, name, default severity) — must reflect `PLUGIN_REGISTRY` live, no hardcoded list.
- CLI3 — `stelarstrike doctor [--config PATH]` — validate config loads, list enabled plugins, warn if scope is empty, check `litellm` is installed when AI is enabled.
- CLI4 — Every `scan` invocation prints the ASCII banner (branding/identity) before any config loading or network activity begins.

## 6. Configuration Contract

This is the authoritative schema. Any code change that adds/renames a config key must update **both** `config/config.example.yaml` and this table.

```yaml
project:
  name: string
  report_dir: string
  log_level: DEBUG|INFO|WARNING|ERROR

engagement:
  name: string
  scope: [glob pattern, ...]           # required for any scan to run (unless empty = allow-all, discouraged)
  out_of_scope: [glob pattern, ...]
  allow_active_payloads: bool          # global gate for exploit-confirming payloads across ALL plugins

discovery:
  enabled: bool                        # crawl for parametrized URLs when the target has none
  max_urls: int
  max_depth: int
  synthetic_params: [string, ...]      # fallback param names guessed when nothing is discoverable

http:
  timeout_seconds: float
  max_concurrency: int
  user_agent: string
  follow_redirects: bool
  verify_tls: bool
  extra_headers: {string: string}

plugins:
  <plugin_id>:
    enabled: bool
    <plugin-specific keys>              # see §5 table + config.example.yaml for current keys per plugin

ai:
  enabled: bool
  provider: string                      # LiteLLM model string
  max_tokens: int
  temperature: float
  roles:
    triage: bool
    report_writer: bool
    payload_advisor: bool

reporting:
  formats: [markdown, json]
  include_raw_evidence: bool
  redact_secrets: bool

notifications:
  slack_webhook_url: string
  discord_webhook_url: string
  notify_on: [scan_complete, critical_finding]
```

Environment variables (`.env`) mirror the most commonly-changed subset of the above under `STELAR_*` names, plus provider API keys — see `.env.example` for the current authoritative list.

## 7. Success Metrics (self-hosted / portfolio project — informal)

- All 8 plugins produce zero false positives against a clean baseline app (e.g. `https://httpbin.org` or a deliberately-hardened test app) — validated manually before each release.
- All 8 plugins produce at least one true-positive finding against a known-vulnerable app (e.g. OWASP Juice Shop / DVWA) used as the test fixture — tracked in `tests/` or a documented manual test log.
- `pytest` suite passes and CI is green on `main` at all times.
- README + PRD stay in sync with `config.example.yaml` and `PLUGIN_REGISTRY` — no undocumented config keys, no unregistered plugin files.

## 8. Roadmap (v1.x and beyond)

Ordered roughly by expected value; not a committed timeline.

### v1.1 — More vuln classes
- RCE (command injection) detection
- XXE
- SSTI (server-side template injection)
- Open redirect
- Insecure deserialization
- HTTP request smuggling (basic CL.TE/TE.CL probing)

### v1.2 — Engagement modes
- Introduce named modes (`bug-bounty`, `ctf`, `internal-audit`) that set sensible defaults for `allow_active_payloads`, plugin subsets, and report format — analogous to presets, not auto-detection magic.

### v1.3 — Deeper discovery
- v1.0 ships a lightweight, one-level-deep same-origin crawler (see §5.5). A future version could go deeper (configurable crawl depth beyond 1), add wordlist-based directory/parameter brute-forcing as an opt-in "loud" mode, and respect `robots.txt`/rate limits more explicitly for larger targets.

### v1.4 — Session/auth handling
- Config-driven login flow (fill a login form once, reuse the resulting session/cookies/bearer token across all plugins) so IDOR/CSRF/etc. can test authenticated endpoints properly.

### v1.5 — Built-in OOB collaborator
- Ship a minimal self-hostable collaborator service (or first-class Interactsh client integration) so SSRF/blind-XXE checks don't require a manually-provided URL.

### v2.0 — Distributed scanning
- Multi-target / multi-worker execution (e.g. via a task queue) for scanning an entire program's scope in one run, plus a results dashboard.

## 9. Open Questions

- OQ1 — Should `payload_advisor` (currently unused) drive payload *generation* for the active-only checks in v1.1's new plugin classes, or stay scoped to suggesting variants of existing payloads? Leaning toward the latter for safety/predictability.
- OQ2 — Should scope matching move from `fnmatch` globs to full URL-pattern matching (path + query awareness) once the discovery/crawler layer (v1.3) lands? Likely yes, since crawler-discovered URLs will have far more path variety than manually-entered ones.
- OQ3 — Report redaction (`reporting.redact_secrets`) is currently a config flag with no implementation — needs a concrete redaction pass (e.g. regex-based secret scrubbing) before it's meaningfully "on."
- OQ4 — Schema hints currently apply to the first matching `sqli` injection entry. Multi-injection schemas (e.g. login + search endpoint both injectable) should be able to apply hints per-URL — needs a URL-aware lookup in `_run_extraction`.

---

## 10. Alternative Schemas

### What they are

A schema is a YAML file in `schemas/` that encodes confirmed knowledge about a
specific type of target — its stack, its injectable endpoints, the UNION column
count, the reflected column position, and bypass payloads that are known to work.

### How StelarStrike uses them

1. At scan start, `core/schema_loader.py` fetches the target root URL and checks
   it against each schema's `fingerprints` list.
2. On a match, the orchestrator skips auto-discovery and column-count enumeration,
   feeds the known `col_count` + `reflected_col` directly to `SQLiExtractor`, and
   adds the schema's known endpoints to the scan queue.
3. The CLI prints `Schema matched: <name>` so you know the fast path was used.

### Benefits per scan

| Without schema | With schema |
|---|---|
| Discovery crawl: 5–20 HTTP requests | Skipped — endpoints known |
| UNION col-count enumeration: up to 15×N requests | Skipped — col_count known |
| Position probe: up to col_count requests | Skipped — reflected_col known |
| AI triage call on generic findings | Skippable for known-pattern targets |

On a 10-column table with 5 injectable fields, a schema match saves ~75+ requests
and the AI triage API call.

### How to create a schema from a writeup

1. Complete a scan (or obtain a writeup — your own, a classmate's, Big Pickle's output, etc.)
2. Paste the writeup to Claude in your StelarStrike conversation.
3. Ask: *"Extract this as a StelarStrike schema YAML for schemas/\<filename\>.yaml"*
4. Claude produces the YAML — save it as `schemas/<target-name>.yaml`.
5. Next scan against the same target type uses it automatically.

### How to update schemas over time

Each new writeup from a course lab, CTF, or bug bounty report is a potential schema.
The pattern is always the same:
> Paste writeup → Claude extracts schema → save file → faster future scans.

### Schema file format contract

Required: `name`, `fingerprints` (at least one), `injections`.
Optional: `stack`, `endpoints`, `additional_findings`.
Full format in `schemas/README.md`.

`fingerprints` supports: `response_contains`, `header_contains`, `status_code`.
All fingerprints in the list must match (AND logic).

---

## 11. Change Log

- **2026-07-10 (2)** — `sqli` rewritten (v3): tests query params and every form field, POST as both form-encoded and JSON body; multi-DBMS error signatures + framework debug-page leaks; baseline false-positive filtering; dual-payload-verified boolean-blind with dynamic-content stripping; login-form auth-bypass detection; bounded UNION column-count confirmation (detection only, no data extraction). Added `stelarstrike scan --plugins id1,id2` (one-off plugin selection override) and `--verbose` (full request/payload debug logging) CLI flags.
- **2026-07-10** — Auto-discovery pulled forward from the v1.3 roadmap into v1.0: `core/discovery.py` crawls same-origin links/forms one level deep and falls back to synthetic common parameter names, so `scan` no longer requires the user to manually supply a query parameter. Orchestrator now fans plugins out across every discovered (in-scope) URL. Added the CLI startup banner.
- **2026-07-09** — v1.0 initial PRD + implementation: 8 plugins (sqli, nosqli, xss, ssrf, csrf, file_upload, idor, jwt), config system, AI layer via LiteLLM, Markdown/JSON reporting, Docker + GitHub Actions CI.

---

## 🔖 Last Change

> This section is overwritten every session. Use Change Log (§11) for full history.

**Date:** 2026-07-12
**Changed by:** Rona (via Claude)

**What changed — Two-phase UNION extraction + Alternative Schemas system:**

**Root cause of extraction still not working:** `_union_scalar` always placed the sentinel in column position 0 (the integer `id` column in MerdekaBank's users table) → PostgreSQL type error → gave up. The reflected column is position 1 (`username`). This was confirmed by simulating the exact target response in a test.

**Fixes in `stelarstrike/plugins/sqli_extract.py`:**
- Added `_reflected_col: int | None` and `_inject_prefix: str` cache attributes.
- Refactored `_union_scalar` into two phases: (1) `_find_col_count_and_position` tries NULL-only probes first (type-safe, confirms column count), then probes each position with the sentinel, detecting and skipping type errors per-position. (2) Once `_col_count` + `_reflected_col` are cached, subsequent calls use them directly (1 HTTP request vs 15+). Tries three injection prefix contexts: string (`'`), numeric (` `), and paren (`')`). Handles `MerdekaBank` case exactly: 10 columns, position 1, confirmed in mocked test.
- `tests/test_sqli_extract.py` fully rewritten with two-phase-aware mocks (29 tests, all passing).

**New: Alternative Schemas system:**
- `schemas/` directory — YAML schema files encoding confirmed target knowledge.
- `schemas/README.md` — format spec, how to create schemas from writeups, how to update over time.
- `schemas/merdekabank_flask_postgresql.yaml` — MerdekaBank schema extracted from Big Pickle writeup: col_count=10, reflected_col=1, bypass=`' OR 1=1-- -`, 10 tables, additional findings.
- `schemas/lab2_43_157.yaml` — starter schema for second lab (43.157.213.172:1337), PENDING — fill in after first scan.
- `stelarstrike/core/schema_loader.py` — fingerprints target on scan start, returns `SchemaMatch` with known parameters. Fingerprint types: `response_contains`, `header_contains`, `status_code`.
- `stelarstrike/core/orchestrator.py` — calls `match_schema()` before discovery; on match, adds schema's known endpoints to scan queue instead of crawling; passes `schema_hints` (col_count, reflected_col, inject_prefix, db_type) to `PluginContext.options["schema_hints"]`.
- `stelarstrike/plugins/sqli.py` — `_run_extraction` reads `options["schema_hints"]` and pre-sets extractor cache attributes, skipping all discovery probes.
- `stelarstrike/cli.py` — `stelarstrike schemas` command lists available schema files; scan output line shows "Schema matched: <name>" on match.
- PRD — new §10 Alternative Schemas documenting the system, format contract, and writeup-to-schema workflow. §11 Change Log, §9 Open Questions updated.

**All 29 tests pass.**

**For second lab — scan and then extract schema:**
```bash
# Scan the second lab
stelarstrike scan "http://43.157.213.172:1337/" --plugins sqli --verbose

# Paste the output to Claude and ask:
# "Extract this as a StelarStrike schema YAML for schemas/lab2_43_157.yaml"
# Then replace schemas/lab2_43_157.yaml with Claude's output.
```

**For MerdekaBank with schema (fast path):**
```bash
# Schema match skips ~75+ HTTP requests and goes straight to known parameters
stelarstrike scan "http://194.233.89.48:5000/" --plugins sqli --verbose
```



