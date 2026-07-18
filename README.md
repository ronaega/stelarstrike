# StelarStrike

<p align="center">
  <img src="./logo.png" alt="StelarStrike logo" width="180" />
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" /></a>
  <a href="https://www.docker.com/"><img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" /></a>
  <a href="https://github.com/features/actions"><img src="https://img.shields.io/badge/GitHub%20Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white" alt="GitHub Actions" /></a>
  <a href="https://opencode.ai/"><img src="https://img.shields.io/badge/OpenCode-000000?style=for-the-badge&logo=openai&logoColor=white" alt="OpenCode" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT License" /></a>
</p>

**StelarStrike** is a modular, AI-powered offensive security framework for **authorized** penetration testing and security research. In v2, it introduces the **agent** concept — each agent is tied to one target, remembers every conversation, and uses AI (OpenCode / Big Pickle model) to perform security actions using built-in skills and tools.

> ⚠️ **Authorized use only.** Only scan targets you own or have explicit written permission to test.

---

## Table of Contents

- [What's New in v2](#whats-new-in-v2)
- [Project Structure](#project-structure)
- [Installation](#installation)
  - [Install OpenCode (AI backend)](#install-opencode-ai-backend)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
  - [General commands](#general-commands)
  - [Agent commands](#agent-commands)
  - [Agent chat](#agent-chat)
- [How Agents Work](#how-agents-work)
- [Skills](#skills)
- [Tools](#tools)
- [Configuration (config.yaml)](#configuration-configyaml)
- [Plugins](#plugins)
- [Uninstalling](#uninstalling)
- [Updating](#updating)
- [Debugging a scan that finds nothing](#debugging-a-scan-that-finds-nothing)
- [Disclaimer](#disclaimer)

---

## What's New in v2

- **Agent system** — create named agents tied to specific targets. Each agent remembers every conversation in a `.md` file and uses AI to plan and execute security actions.
- **OpenCode AI backend** — powered by [OpenCode](https://opencode.ai) with `opencode/big-pickle` as the default model. No API keys or Python AI packages needed.
- **Skills** — structured security knowledge bases (SQL Injection, XSS, CSRF, IDOR, File Inclusion, Web Cache Deception) that agents use when executing actions.
- **Tools** — curated tool list that agents reference for recommendations during actions.
- **config.yaml is now optional** — scope comes from the agent file. Run scans with zero configuration.
- **Schemas removed** — the agent + AI system handles target understanding dynamically.

---

## Project Structure

```
stelarstrike/               ← project root
├── agents/                 ← agent .md files (git-ignored, private)
├── assets/                 ← Python package (core framework)
│   ├── core/               ← config, orchestrator, ai_client, agent engine
│   ├── plugins/            ← vulnerability plugins (sqli, xss, csrf, idor, ...)
│   ├── skills/             ← security knowledge bases used by agents
│   ├── tools/              ← tools-list.json
│   └── utils/              ← shared helpers
├── config/                 ← config.yaml (optional, not committed)
├── reports/                ← scan reports (git-ignored)
└── tests/                  ← test suite
```

---

## Installation

Requires Python **3.10+**.

```bash
git clone https://github.com/ronaega/stelarstrike.git
cd stelarstrike

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
```

### Install OpenCode (AI backend)

StelarStrike uses **OpenCode** for all AI features. Install it once:

```bash
curl -fsSL https://opencode.ai/install | bash

# Verify
opencode --version

# See available models (default is opencode/big-pickle)
opencode models
```

OpenCode is optional — all scans and commands work without it; AI features (narrative, triage, agent responses) are simply skipped with a clear message.

```bash
# Verify full install
stelarstrike --version
stelarstrike doctor
```

---

## Quick Start

```bash
# 1. Create an agent for your target
stelarstrike --createagent rex "http://target.example.com/"

# 2. Ask it a question
stelarstrike rex "what vulnerabilities should I look for on a Flask login page?"

# 3. Ask it to take action (it will confirm first)
stelarstrike rex "scan for SQL injection"

# 4. Run a direct scan without an agent
stelarstrike scan "http://target.example.com/" --plugins sqli --verbose
```

---

## Command Reference

### General commands

```bash
stelarstrike scan <target> [options]   # run vulnerability scan
stelarstrike plugins                   # list all vulnerability plugins
stelarstrike --skills                  # list available skills
stelarstrike --tools                   # list available tools
stelarstrike --version                 # show version
stelarstrike doctor                    # check config, OpenCode, plugins
```

**scan options:**
```
--config / -c   path to config.yaml (optional — defaults kick in if missing)
--plugins / -p  comma-separated plugin IDs, e.g. --plugins sqli,xss
--formats       report formats: markdown,json (default: both)
--verbose / -v  log every payload and response
```

### Agent commands

```bash
stelarstrike --createagent <name> <target>   # create agent (name: 2-7 alphanumeric)
stelarstrike --deleteagent <name>            # delete agent and its history
stelarstrike --agents                        # list all agents and targets
```

**Agent name rules:**
- 2 to 7 characters, letters and numbers only
- Cannot be: `stelarstrike`, `agent`
- Examples: `rex`, `lab01`, `alpha7`

### Agent chat

```bash
stelarstrike <agent> "<prompt>"
```

The prompt **must** be in double quotes. Examples:

```bash
stelarstrike rex "what is SQL injection?"
stelarstrike rex "scan for XSS vulnerabilities"
stelarstrike rex "do a full security assessment"
stelarstrike rex "explain what you found"
```

---

## How Agents Work

Each agent is a `.md` file in `agents/` with this structure:

```
---
created: 2026-07-14T09:00:00
target: http://target.example.com/
last_chat: 2026-07-14T10:30:00
total_response_chars: 3421
status: idle
---

# Agent: rex
**Target:** http://target.example.com/

---

### User | 2026-07-14T09:05:00
scan for SQL injection

### Agent | 2026-07-14T09:05:12
Do you want me to scan / test (SQL Injection) on the target http://target.example.com/?
...

---
```

**Conversation flow:**
1. **Question prompts** (what, how, explain, etc.) → direct AI answer, no banner
2. **Action prompts** (scan, test, do, check, exploit, etc.) → agent shows banner + asks for confirmation
3. User replies **yes** → agent executes using relevant skill + tools, writes full report to the `.md` file
4. User replies **no** → action cancelled, conversation continues

**All responses are appended to the agent's `.md` file** — full conversation history is always available.

---

## Skills

Skills are security knowledge bases that agents use when executing actions.

```bash
stelarstrike --skills
```

| Skill | Description |
|-------|-------------|
| SQL Injection | Union-based, blind, error-based, time-based SQLi |
| XSS Injection | Reflected, stored, DOM XSS, WAF bypass techniques |
| File Inclusion | LFI/RFI, PHP wrappers, LFI-to-RCE |
| Cross-Site Request Forgery | CSRF bypass techniques |
| Insecure Direct Object References | IDOR enumeration and exploitation |
| Web Cache Deception | Cache poisoning and deception |

Skills are in `assets/skills/` — original text Copyright (c) 2019 Swissky.

---

## Tools

```bash
stelarstrike --tools
```

Lists all tools agents may recommend or use during action execution (SQLMap, Nmap, Burp Suite, etc.).

---

## Configuration (config.yaml)

`config.yaml` is **optional** in v2. When it does not exist, StelarStrike uses sensible defaults:
- All plugins enabled
- No scope restriction (warn-only — only scan targets you are authorized to test)
- OpenCode Big Pickle model
- 15s timeout, 10 concurrent requests

When using agents, **scope is set automatically** from the target you specified in `--createagent`.

For direct `stelarstrike scan` usage, create `config/config.yaml`:

```bash
cp config/config.example.yaml config/config.yaml
```

Minimum useful config:

```yaml
engagement:
  name: "my-engagement"
  scope:
    - "http://target.example.com/*"
  allow_active_payloads: true   # enables UNION extraction, file uploads, etc.
```

`config/config.yaml` is git-ignored — never committed.

**AI model** — set in `.env`:

```dotenv
STELAR_AI_ENABLED=true
OPENCODE_MODEL=opencode/big-pickle   # default — change with: opencode models
```

---

## Plugins

```bash
stelarstrike plugins
```

| ID | Name | Severity |
|----|------|----------|
| `sqli` | SQL Injection | high |
| `nosqli` | NoSQL Injection | high |
| `xss` | Cross-Site Scripting | medium |
| `ssrf` | Server-Side Request Forgery | high |
| `csrf` | Cross-Site Request Forgery | medium |
| `file_upload` | Insecure File Upload | high |
| `idor` | Insecure Direct Object Reference | high |
| `jwt` | JWT Vulnerabilities | high |

---

## Uninstalling

```bash
# Deactivate venv first
deactivate

# Remove everything
rm -rf /path/to/stelarstrike

# Or just uninstall the package (if installed globally)
pip uninstall stelarstrike -y
```

---

## Updating

```bash
git pull origin main
pip install -e ".[dev]"

# Check for new config options
diff config/config.yaml config/config.example.yaml
```

If `git pull` fails due to local edits:
```bash
git stash
git pull origin main
git stash pop
```

---

## Debugging a scan that finds nothing

1. **Run with `--verbose`** — shows every payload sent and response received:
   ```bash
   stelarstrike scan "http://target/" --plugins sqli --verbose
   ```

2. **Check Discovery log** — look for `Discovery: N URL(s) queued`. If only 1 URL, try pointing at a specific page with a form or parameter.

3. **Check `allow_active_payloads`** — UNION extraction, file upload probes, and auth bypass confirmation all require it to be `true`.

4. **Via agent** — ask the agent to explain what it found:
   ```bash
   stelarstrike rex "what did you find? explain the results"
   ```

---

## Disclaimer

StelarStrike is provided for **authorized security testing and educational purposes only**. Only run it against systems you own or have explicit written permission to test. The authors and contributors are not responsible for misuse.
