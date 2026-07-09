# ⭐ StelarStrike

**StelarStrike** is a modular, AI-assisted web vulnerability orchestration framework for **authorized** penetration testing and security research. It coordinates a set of plugin-based vulnerability checks against a target, optionally uses an LLM to triage findings and draft a report narrative, and outputs a clean Markdown/JSON report.

> ⚠️ **Authorized use only.** StelarStrike is built for testing systems you own or have explicit written permission to test (bug bounty programs, CTFs, your own lab, or a client engagement with a signed scope). It enforces a scope allowlist and fails closed by default — see [Scope Enforcement](#scope-enforcement).

---

## Table of Contents

- [Why StelarStrike](#why-stelarstrike)
- [v1.0 Scope](#v10-scope)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
  - [1. Environment variables (`.env`)](#1-environment-variables-env)
  - [2. Main config (`config/config.yaml`)](#2-main-config-configconfigyaml)
  - [3. Configuring the AI model](#3-configuring-the-ai-model)
  - [4. Configuring individual plugins](#4-configuring-individual-plugins)
- [Scope Enforcement](#scope-enforcement)
- [Usage](#usage)
- [Running with Docker](#running-with-docker)
- [Reports](#reports)
- [Extending StelarStrike (adding a new vulnerability class)](#extending-stelarstrike-adding-a-new-vulnerability-class)
- [Testing](#testing)
- [CI/CD](#cicd)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)

---

## Why StelarStrike

Most single-purpose scanners check one vulnerability class and stop. StelarStrike is an **orchestrator**: it runs a set of independent vulnerability plugins concurrently against a target, normalizes every result into one `Finding` model, and hands the aggregate to an LLM for triage (priority ranking, false-positive hints) and report writing — while remaining fully usable with AI turned off.

Design principles:

- **Plugin-first.** Every vulnerability class is an isolated, independently-testable plugin. Adding a new one never requires touching the orchestrator.
- **Fail closed on scope.** Nothing gets actively tested unless it matches an explicit allowlist in `config.yaml`.
- **Passive by default, active by opt-in.** Exploit-confirming payloads (time-based SQLi, `alg:none` JWT forgery, file upload probes, etc.) only fire when `engagement.allow_active_payloads: true` is set.
- **AI is a layer, not a dependency.** Every plugin produces useful, structured output with `ai.enabled: false`. AI only adds triage/report polish on top.
- **Provider-agnostic AI.** Powered by [LiteLLM](https://github.com/BerriAI/litellm), so switching between Anthropic, OpenAI, Azure OpenAI, or a fully local Ollama model is a one-line config change.

## v1.0 Scope

Version 1.0 ships with **8 vulnerability class plugins**:

| Plugin ID     | Vulnerability Class              | CWE      |
| ------------- | --------------------------------- | -------- |
| `sqli`        | SQL Injection                     | CWE-89   |
| `nosqli`      | NoSQL Injection (MongoDB-style)   | CWE-943  |
| `xss`         | Cross-Site Scripting              | CWE-79   |
| `ssrf`        | Server-Side Request Forgery       | CWE-918  |
| `csrf`        | Cross-Site Request Forgery        | CWE-352  |
| `file_upload` | Insecure File Upload              | CWE-434  |
| `idor`        | Insecure Direct Object Reference  | CWE-639  |
| `jwt`         | JSON Web Token vulnerabilities    | CWE-347 / CWE-798 / CWE-613 |

Everything else — engagement modes, additional vuln classes, CI/CD scanning integration, distributed scanning — is intentionally deferred. See [`PRD.md`](./PRD.md) for the full roadmap and design rationale, and [Roadmap](#roadmap) below for a summary.

## Architecture

```
stelarstrike/
├── cli.py                  # Typer CLI: scan / plugins / doctor
├── core/
│   ├── config.py           # Loads .env + config.yaml, resolves ${VAR} placeholders
│   ├── target.py           # Target model + scope enforcement (fail-closed)
│   ├── orchestrator.py     # Discovers enabled plugins, runs them concurrently, builds report
│   ├── ai_client.py        # LiteLLM wrapper: triage + report narrative (optional)
│   └── report.py           # Finding model + Markdown/JSON report writer
├── plugins/
│   ├── base.py              # VulnerabilityPlugin ABC + PluginContext
│   ├── __init__.py          # PLUGIN_REGISTRY — single source of truth for enabled plugins
│   ├── sqli.py / nosqli.py / xss.py / ssrf.py / csrf.py
│   └── file_upload.py / idor.py / jwt_vuln.py
└── utils/
    ├── logger.py            # rich-based structured logging
    └── http_client.py       # form/param/URL parsing helpers shared by plugins
```

**Flow:** `cli.scan` → loads `Settings` → `Orchestrator.run(target_url)` → scope check → instantiate every enabled plugin from `PLUGIN_REGISTRY` → run concurrently via `asyncio` (bounded by `http.max_concurrency`) → collect `Finding`s into `ReportBuilder` → optional AI triage/narrative → write `.md` / `.json` to `reports/`.

## Installation

Requires Python **3.10+**.

```bash
git clone https://github.com/<your-username>/stelarstrike.git
cd stelarstrike

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
# or, without editable/dev extras:
# pip install -r requirements.txt
```

Verify the install:

```bash
stelarstrike --help
stelarstrike plugins
```

## Configuration

StelarStrike is configured in two layers: a **`.env`** file for secrets/environment-specific values, and a **`config/config.yaml`** file for engagement and plugin behavior. `config.yaml` can reference `.env` values using `${VAR_NAME}` or `${VAR_NAME:-default}` syntax.

### 1. Environment variables (`.env`)

```bash
cp .env.example .env
```

Then edit `.env`. Key sections:

```dotenv
# Which AI provider/model to use (LiteLLM provider string)
STELAR_AI_PROVIDER=anthropic/claude-sonnet-4-6
STELAR_AI_ENABLED=true

# Fill in ONLY the key matching your chosen provider
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=
AZURE_API_KEY=
AZURE_API_BASE=
AZURE_API_VERSION=

# Fully local model — no API key needed
OLLAMA_BASE_URL=http://localhost:11434

# Safety switches
STELAR_REQUIRE_SCOPE_FILE=true
STELAR_ALLOW_ACTIVE_PAYLOADS=false
```

Full list of variables and comments: [`.env.example`](./.env.example).

### 2. Main config (`config/config.yaml`)

```bash
cp config/config.example.yaml config/config.yaml
```

`config/config.yaml` is git-ignored on purpose (see `.gitignore`) — it's meant to hold your **real** engagement scope, which you should not commit. Only `config.example.yaml` is tracked in git.

Minimum you need to edit before your first scan:

```yaml
engagement:
  name: "my-first-engagement"
  scope:
    - "https://target.example.com/*"   # <-- your authorized target(s)
  allow_active_payloads: false          # keep false until you've reviewed what "active" means (see below)
```

### 3. Configuring the AI model

StelarStrike uses [LiteLLM](https://docs.litellm.ai/docs/providers) as a universal AI client, so `ai.provider` in `config.yaml` (or `STELAR_AI_PROVIDER` in `.env`) accepts any LiteLLM provider string:

| Provider | `ai.provider` value | Required env var |
|---|---|---|
| Anthropic (Claude) | `anthropic/claude-sonnet-4-6` | `ANTHROPIC_API_KEY` |
| OpenAI | `openai/gpt-4o-mini` | `OPENAI_API_KEY` |
| Azure OpenAI | `azure/<your-deployment-name>` | `AZURE_API_KEY`, `AZURE_API_BASE`, `AZURE_API_VERSION` |
| Local (Ollama) | `ollama/llama3.1` | none — set `OLLAMA_BASE_URL` |

To disable AI entirely (fully deterministic, offline-capable operation):

```yaml
ai:
  enabled: false
```

AI is used for three independently-toggleable **roles** (`config.yaml` → `ai.roles`):

```yaml
ai:
  roles:
    triage: true           # rank/deduplicate findings by exploitability
    report_writer: true    # draft the executive-summary narrative in the report
    payload_advisor: false # suggest payload variants (only meaningful with allow_active_payloads: true)
```

### 4. Configuring individual plugins

Each plugin is toggled and tuned under `plugins:` in `config.yaml`:

```yaml
plugins:
  sqli:
    enabled: true
    techniques: ["error-based", "boolean-blind", "time-blind"]
    time_delay_seconds: 5
  nosqli:
    enabled: true
  xss:
    enabled: true
    contexts: ["reflected"]
  ssrf:
    enabled: true
    collaborator_url: ""     # your own Interactsh/Burp Collaborator/webhook.site URL
  csrf:
    enabled: true
    check_samesite: true
  file_upload:
    enabled: true
    test_extensions: [".php", ".php5", ".phtml", ".svg", ".jsp", ".asp"]
  idor:
    enabled: true
    id_param_hints: ["id", "user_id", "uid", "account", "order_id"]
  jwt:
    enabled: true
    checks: ["alg-none", "weak-secret", "kid-injection", "expired-token-reuse"]
```

Set `enabled: false` on any plugin you don't want to run for a given engagement — disabled plugins are skipped entirely (no network calls, no findings).

**Passive vs. active checks:** every plugin runs safe, passive/detection-only checks by default. Checks that require sending an exploit-confirming payload (time-based SQLi, `alg:none` JWT forgery, real file upload probes, SSRF out-of-band probes) are additionally gated by the top-level:

```yaml
engagement:
  allow_active_payloads: false   # set true only once you've confirmed you're authorized for active testing
```

## Scope Enforcement

Before any plugin runs, `stelarstrike/core/target.py` checks the target URL/host against `engagement.scope` and `engagement.out_of_scope` (glob patterns). If the target doesn't match an entry in `scope`, or matches an entry in `out_of_scope`, the scan is refused with a `ScopeError` before a single request is sent.

```yaml
engagement:
  scope:
    - "https://target.example.com/*"
    - "*.staging.example.com"
  out_of_scope:
    - "https://target.example.com/admin/*"
```

## Usage

```bash
# List all registered plugins
stelarstrike plugins

# Sanity-check your configuration + AI connectivity
stelarstrike doctor

# Run a full scan
stelarstrike scan "https://target.example.com/page?id=1" \
  --config config/config.yaml \
  --formats markdown,json
```

Sample output:

```
StelarStrike v0.1.0 — scanning https://target.example.com/page?id=1
Engagement: my-first-engagement | AI: on (anthropic/claude-sonnet-4-6)

                     Findings — my-first-engagement
┏━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Severity     ┃ Plugin  ┃ Title                            ┃ Parameter ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ HIGH         │ sqli    │ SQL Injection (error-based)       │ id        │
│ MEDIUM       │ csrf    │ CSRF: form lacks anti-CSRF token  │ /login    │
└──────────────┴─────────┴──────────────────────────────────┴───────────┘
2 total finding(s).
Report written: reports/my-first-engagement-20260709-142200.md
Report written: reports/my-first-engagement-20260709-142200.json
```

## Running with Docker

```bash
docker build -t stelarstrike:local .

docker run --rm \
  --env-file .env \
  -v "$(pwd)/config:/app/config:ro" \
  -v "$(pwd)/reports:/app/reports" \
  stelarstrike:local scan "https://target.example.com" --config /app/config/config.yaml
```

Or with docker-compose (edit the target URL in `docker-compose.yml` first):

```bash
docker compose up --build
```

## Reports

Reports are written to `reports/` (configurable via `STELAR_REPORT_DIR` / `project.report_dir`) as:

- **`<engagement>-<timestamp>.md`** — human-readable report: AI-drafted executive summary (or a deterministic fallback if AI is disabled), findings grouped and sorted by severity, evidence, and remediation guidance.
- **`<engagement>-<timestamp>.json`** — the same data in structured form, for feeding into other tooling (ticketing systems, dashboards, CI gates).

`reports/` is git-ignored by default — engagement findings can be sensitive and generally shouldn't be committed to a public repo.

## Extending StelarStrike (adding a new vulnerability class)

1. Create `stelarstrike/plugins/your_vuln.py`:

```python
from stelarstrike.core.report import Finding
from stelarstrike.plugins.base import VulnerabilityPlugin

class YourVulnPlugin(VulnerabilityPlugin):
    id = "your_vuln"
    name = "Your Vulnerability Class"
    default_severity = "medium"

    async def run(self) -> list[Finding]:
        findings = []
        # ... your detection logic using self.get()/self.post() ...
        return findings
```

2. Register it in `stelarstrike/plugins/__init__.py`:

```python
from stelarstrike.plugins.your_vuln import YourVulnPlugin
PLUGIN_REGISTRY["your_vuln"] = YourVulnPlugin
```

3. Add a matching section to `config/config.example.yaml` under `plugins:`.

That's it — the orchestrator, CLI, and reporting layer all pick it up automatically through `PLUGIN_REGISTRY`.

## Testing

```bash
pytest -v
ruff check stelarstrike tests
mypy stelarstrike --ignore-missing-imports
```

## CI/CD

`.github/workflows/ci.yml` runs on every push/PR to `main`:

1. Install deps, lint with `ruff`, type-check with `mypy`, run `pytest`.
2. Build the Docker image and sanity-check it (`stelarstrike plugins` inside the container).

No live scanning happens in CI by default — wire up `STELAR_CI_TARGET_URL` as a repo secret if you want to add an authorized-target smoke scan job later.

## Roadmap

See [`PRD.md`](./PRD.md) for the full breakdown. Summary of what's deliberately **out of scope for v1.0**:

- Additional vuln classes (RCE, XXE, SSTI, deserialization, HTTP request smuggling, open redirect, business logic, race conditions)
- Engagement modes (bug-bounty / red-team / CTF presets)
- Distributed/parallel multi-target scanning
- Built-in OOB collaborator server (currently bring-your-own)
- Web UI / dashboard
- Authenticated scanning session management (login flows, multi-step auth)

## Disclaimer

StelarStrike is provided for **authorized security testing and educational purposes only**. Only run it against systems you own or have explicit, documented permission to test. The authors and contributors are not responsible for misuse or damage caused by this tool. Running active checks (`engagement.allow_active_payloads: true`) against a target without authorization is illegal in most jurisdictions.
