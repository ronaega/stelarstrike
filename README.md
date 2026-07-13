# StelarStrike

<p align="center">
  <img src="./logo.png" alt="StelarStrike logo" width="180" />
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT License" /></a>
</p>

**StelarStrike** is a modular, AI-assisted web vulnerability orchestration framework for **authorized** penetration testing and security research. It coordinates a set of plugin-based vulnerability checks against a target, optionally uses an LLM to triage findings and draft a report narrative, and outputs a clean Markdown/JSON report.

> **Authorized use only.** StelarStrike is built for testing systems you own or have explicit written permission to test. It enforces a scope allowlist and fails closed by default.

---

## Table of Contents

- [Why StelarStrike](#why-stelarstrike)
- [Methodology](#methodology)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Reports](#reports)
- [Extending StelarStrike](#extending-stelarstrike)
- [Disclaimer](#disclaimer)

---

## Why StelarStrike

Most single-purpose scanners check one vulnerability class and stop. StelarStrike is an **orchestrator**: it runs a set of independent vulnerability plugins concurrently against a target, normalizes every result into one `Finding` model, and hands the aggregate to an LLM for triage and report writing.

Design principles:

- **Plugin-first.** Every vulnerability class is an isolated, independently-testable plugin.
- **Fail closed on scope.** Nothing gets actively tested unless it matches an explicit allowlist.
- **Passive by default, active by opt-in.** Exploit-confirming payloads only fire when `allow_active_payloads: true`.
- **AI is a layer, not a dependency.** Every plugin produces useful output with `ai.enabled: false`.

---

## Methodology

StelarStrike implements the **Big Pickle methodology** — a proven 6-phase approach to penetration testing:

### Phase 1: Reconnaissance
- Spider/crawl target to map all endpoints
- Extract forms, links, and parameters
- Technology fingerprinting (headers, errors, content)

### Phase 2: Endpoint Enumeration
- Discover all testable endpoints and parameters
- Identify hidden endpoints (admin, debug, test)
- Map parameter types and expected values

### Phase 3: Manual Payload Testing
- Test each parameter with targeted payloads
- Error-based, boolean-blind, time-blind, UNION-based
- Document which parameters are vulnerable

### Phase 4: Automated Tool Verification
- Use automated tools to verify findings
- sqlmap for SQLi, dalfox for XSS, ffuf for directories
- Expand and confirm manual findings

### Phase 5: Data Extraction
- Extract data from confirmed vulnerabilities
- Focus on high-value tables (users, admin, auth)
- Document potential impact

### Phase 6: Documentation
- Record all findings with evidence
- Capture proof-of-concept requests/responses
- Write executive summary with remediation

---

## Architecture

```
stelarstrike/
├── cli.py                  # Typer CLI: scan / plugins / doctor
├── core/
│   ├── config.py           # Loads .env + config.yaml
│   ├── target.py           # Target model + scope enforcement
│   ├── orchestrator.py     # Runs plugins concurrently, builds report
│   ├── ai_client.py        # OPENCODE wrapper (Big Pickle)
│   └── report.py           # Finding model + report writer
├── plugins/
│   ├── base.py             # VulnerabilityPlugin ABC
│   ├── __init__.py         # PLUGIN_REGISTRY
│   ├── sqli.py             # SQL Injection
│   ├── nosqli.py           # NoSQL Injection
│   ├── xss.py              # Cross-Site Scripting
│   ├── ssrf.py             # Server-Side Request Forgery
│   ├── csrf.py             # Cross-Site Request Forgery
│   ├── file_upload.py      # Insecure File Upload
│   ├── idor.py             # Insecure Direct Object Reference
│   └── jwt_vuln.py         # JWT vulnerabilities
└── utils/
    ├── logger.py           # Structured logging
    └── http_client.py      # HTTP helpers
```

---

## Installation

Requires Python **3.10+**.

```bash
git clone https://github.com/ronaega/stelarstrike.git
cd stelarstrike

python -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"
```

Verify:

```bash
stelarstrike --help
stelarstrike plugins
```

---

## Configuration

### 1. Environment variables (`.env`)

```bash
cp .env.example .env
```

Key settings:

```dotenv
# AI provider (OPENCODE Big Pickle)
STELAR_AI_PROVIDER=opencode/big-pickle
STELAR_AI_ENABLED=true

# Safety switches
STELAR_REQUIRE_SCOPE_FILE=true
STELAR_ALLOW_ACTIVE_PAYLOADS=false
```

### 2. Main config (`config/config.yaml`)

```bash
cp config/config.example.yaml config/config.yaml
```

Minimum to edit:

```yaml
engagement:
  name: "my-engagement"
  scope:
    - "https://target.example.com/*"
  allow_active_payloads: false
```

### 3. Plugin configuration

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
  ssrf:
    enabled: true
  csrf:
    enabled: true
  file_upload:
    enabled: true
  idor:
    enabled: true
  jwt:
    enabled: true
```

### 4. Auto-discovery

Plugins need parameters to test. Discovery crawls the target to find them:

```yaml
discovery:
  enabled: true
  max_urls: 10
  max_depth: 1
  synthetic_params: ["id", "page", "search", "q", "user_id"]
```

---

## Usage

```bash
# List plugins
stelarstrike plugins

# Full scan
stelarstrike scan "https://target.example.com/"

# Specific plugins
stelarstrike scan "https://target.example.com/" --plugins sqli,xss

# Verbose output
stelarstrike scan "https://target.example.com/" --plugins sqli --verbose
```

### SQLi Scanning Example

```bash
# Basic SQLi scan
stelarstrike scan "http://target.com/?id=1" --plugins sqli

# With active payloads (UNION, time-based)
stelarstrike scan "http://target.com/" --plugins sqli --verbose

# Test forms
stelarstrike scan "http://target.com/login" --plugins sqli
```

The SQLi plugin tests:
- Error-based injection (MySQL, PostgreSQL, MSSQL, SQLite, Oracle)
- Boolean-blind injection
- Time-blind injection
- UNION-based column counting
- Form field injection

---

## Reports

Reports are written to `reports/` as:

- **`<engagement>-<timestamp>.md`** — Human-readable report with executive summary, findings, evidence, remediation.
- **`<engagement>-<timestamp>.json`** — Structured data for other tooling.

---

## Extending StelarStrike

1. Create `stelarstrike/plugins/your_vuln.py`:

```python
from stelarstrike.core.report import Finding
from stelarstrike.plugins.base import VulnerabilityPlugin

class YourVulnPlugin(VulnerabilityPlugin):
    id = "your_vuln"
    name = "Your Vulnerability Class"

    async def run(self) -> list[Finding]:
        findings = []
        # Your detection logic
        return findings
```

2. Register in `plugins/__init__.py`:

```python
from stelarstrike.plugins.your_vuln import YourVulnPlugin
PLUGIN_REGISTRY["your_vuln"] = YourVulnPlugin
```

3. Add config section to `config/config.yaml`.

---

## Tools Reference

StelarStrike can suggest external tools for deeper testing:

| Tool | Purpose | Command |
|------|---------|---------|
| sqlmap | SQL injection | `sqlmap -u "target/?id=1" --batch` |
| dalfox | XSS scanning | `dalfox url "target/?q=test"` |
| ffuf | Directory brute-force | `ffuf -u "target/FUZZ" -w wordlist.txt` |
| nikto | Web server scan | `nikto -h target` |
| whatweb | Technology fingerprint | `whatweb target` |

---

## Disclaimer

StelarStrike is provided for **authorized security testing and educational purposes only**. Only run it against systems you own or have explicit, documented permission to test. The authors are not responsible for misuse or damage caused by this tool. Suwun!
