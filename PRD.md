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
- NG3 — Not a fuzzer/brute-forcer — no wordlist-based directory or parameter discovery in v1.0 (candidate for v1.x, see §8).
- NG4 — No built-in OOB collaborator server — SSRF OOB checks rely on a user-supplied collaborator URL.
- NG5 — No GUI/dashboard — CLI + Markdown/JSON reports only.

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
| 1 | `sqli` | Error-based: inject `'`, match DB error signatures. Boolean-blind: compare response length between TRUE/FALSE injected conditions. | Time-blind: `SLEEP()`-style payload, compare latency vs. baseline. | high | CWE-89 |
| 2 | `nosqli` | Send `$ne`/operator payload as JSON body value, compare status/length against baseline; match Mongo/BSON error signatures. | (same checks; no separate active-only path in v1.0) | high | CWE-943 |
| 3 | `xss` | Inject a unique marker with HTML metacharacters into query params and form fields, check for unescaped reflection. | Full `<script>` payload round-trip confirmation. | medium (high if confirmed) | CWE-79 |
| 4 | `ssrf` | Flag parameters by name/value heuristics (url, redirect, webhook, already-a-URL, ...). | Send out-of-band probe to a user-configured collaborator URL. | high (low/informational for heuristic-only) | CWE-918 |
| 5 | `csrf` | Parse forms, flag state-changing (`POST`) forms missing a CSRF token field; check `SameSite` cookie attribute as partial mitigation. | — (no active-only path; this class is inherently passive) | medium (high if no SameSite either, low if SameSite present) | CWE-352 |
| 6 | `file_upload` | Locate upload forms. | Upload inert probe files with dangerous extensions (`.php`, `.jsp`, ...), check acceptance + web-reachability of the stored file. | high (critical if reachability confirmed) | CWE-434 |
| 7 | `idor` | Match parameter names against identifier hints; classify integer vs. UUID identifiers. | Request a neighboring integer ID with the same session, compare response. | high (informational for UUID-only heuristic flag) | CWE-639 |
| 8 | `jwt` | Locate JWT in Authorization header/cookies. Decode (unverified) and check `kid` header for injection patterns; brute-force HS256 signature against a small common-secret wordlist. | `alg:none` forgery test; expired-token-reuse test (re-signed with a probe key). | high (critical if `alg:none` or weak-secret confirmed) | CWE-347 / CWE-798 / CWE-613 |

### 5.1 Orchestration requirements

- OR1 — Plugins run concurrently via `asyncio.gather`, bounded by `http.max_concurrency` (shared `asyncio.Semaphore`).
- OR2 — Scope is enforced once, before any plugin instantiates (`core/target.py::enforce_scope`), and raises `ScopeError` which the CLI surfaces as a clean error + exit code 1 (never a stack trace).
- OR3 — A plugin raising an unhandled exception is caught at the orchestrator level, logged, and excluded from the report — it must not abort other plugins.
- OR4 — All plugins share one `httpx.AsyncClient` instance per scan (connection pooling, consistent headers/cookies/timeout).

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

- CLI1 — `stelarstrike scan <target> [--config PATH] [--formats markdown,json]` — run a scan.
- CLI2 — `stelarstrike plugins` — list all registered plugins (id, name, default severity) — must reflect `PLUGIN_REGISTRY` live, no hardcoded list.
- CLI3 — `stelarstrike doctor [--config PATH]` — validate config loads, list enabled plugins, warn if scope is empty, check `litellm` is installed when AI is enabled.

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

### v1.3 — Discovery layer
- Optional lightweight crawler to enumerate URLs/forms/params from a starting point, feeding the plugin layer instead of requiring the user to enumerate every endpoint URL manually.
- Optional wordlist-based parameter/endpoint discovery (opt-in, since this is inherently noisier/louder).

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

## 10. Change Log

- **2026-07-09** — v1.0 initial PRD + implementation: 8 plugins (sqli, nosqli, xss, ssrf, csrf, file_upload, idor, jwt), config system, AI layer via LiteLLM, Markdown/JSON reporting, Docker + GitHub Actions CI.
