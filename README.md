# StelarStrike

<p align="center">
  <img src="./logo.png" alt="StelarStrike logo" width="180" />
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" /></a>
  <a href="https://www.docker.com/"><img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" /></a>
  <a href="https://github.com/features/actions"><img src="https://img.shields.io/badge/GitHub%20Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white" /></a>
  <a href="https://opencode.ai/"><img src="https://img.shields.io/badge/OpenCode-000000?style=for-the-badge&logo=openai&logoColor=white" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" /></a>
</p>

**StelarStrike** is a modular, AI-powered web security testing framework for **authorized** penetration testing. It uses agents — each tied to one target — that remember conversations, use built-in security skills, and perform automated vulnerability scans powered by OpenCode (Big Pickle model).

> ⚠️ **For authorized use only.** Only test systems you own or have written permission to test.

---

## Table of Contents

- [Project Structure](#project-structure)
- [Installation](#installation)
- [Setup](#setup)
- [Commands](#commands)
- [Agents](#agents)
- [Skills and Tools](#skills-and-tools)
- [Plugins](#plugins)
- [Uninstalling](#uninstalling)
- [Updating](#updating)

---

## Project Structure

```
stelarstrike/
├── agents/          ← your agent conversation files (private, not shared)
├── assets/          ← framework code (plugins, skills, tools, core logic)
├── config/          ← optional configuration
├── reports/         ← scan output files
└── tests/           ← test suite
```

---

## Installation

Requires **Python 3.10+**.

**Step 1 — Clone and install:**
```bash
git clone https://github.com/ronaega/stelarstrike.git
cd stelarstrike

python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
```

**Step 2 — Install OpenCode (AI backend):**
```bash
curl -fsSL https://opencode.ai/install | bash
```

OpenCode is the AI engine. The default model is `opencode/big-pickle`. Run `opencode models` to see all available models.

OpenCode is optional — all scans still work without it, but AI features (agent chat, triage, report writing) will be skipped.

**Step 3 — Set up environment:**
```bash
cp .env.example .env
# Edit .env if you want to change the AI model or log level
```

**Verify everything works:**
```bash
stelarstrike --version
stelarstrike --help
```

---

## Setup

### Configuration (optional)

StelarStrike works **without any configuration file**. When you create an agent, the target is set automatically — no need to write scope rules manually.

If you want to use the direct `scan` command (without an agent), create a config file:
```bash
cp config/config.example.yaml config/config.yaml
# Edit config/config.yaml with your target scope
```

> **Note for people who clone this repo:** `config/config.yaml` is excluded from the repository on purpose — it would contain your private target details. You always need to create your own copy from `config/config.example.yaml`. Same goes for `.env` — you create your own from `.env.example`.

### Environment file

The `.env` file contains personal settings like which AI model to use. It is also excluded from the repository so your settings stay private.

```dotenv
STELAR_AI_ENABLED=true
OPENCODE_MODEL=opencode/big-pickle
STELAR_LOG_LEVEL=INFO
```

---

## Commands

```
stelarstrike --help                              show all commands
stelarstrike --version                           show version
stelarstrike --skills                            list available skills
stelarstrike --tools                             list available tools
stelarstrike --agents                            list all your agents
stelarstrike --createagent <name> <target>       create a new agent
stelarstrike --deleteagent <name>                delete an agent
stelarstrike scan <target> [options]             run a direct scan
stelarstrike plugins                             list vulnerability plugins
stelarstrike doctor                              check installation health
```

**scan options:**
```
--config / -c   path to config.yaml (optional)
--plugins / -p  specific plugins only, e.g. --plugins sqli,xss
--formats       output formats: markdown,json (default: both)
--verbose / -v  show every payload and response
```

---

## Agents

Agents are the main way to use StelarStrike. Each agent is assigned to one target and keeps a full conversation history.

**Agent name rules:**
- 2 to 7 characters, letters and numbers only
- Cannot use the words: `stelarstrike` or `agent`
- Examples: `rex`, `lab01`, `r3x`, `alpha`

**Creating and using an agent:**
```bash
# Create
stelarstrike --createagent rex "http://194.233.89.48:5000/"

# Ask a question (no banner, direct answer)
stelarstrike rex "what is SQL injection?"

# Ask for an action (shows banner, asks for confirmation first)
stelarstrike rex "scan for SQL injection"
stelarstrike rex "do a full security test"

# List all agents
stelarstrike --agents

# Delete
stelarstrike --deleteagent rex
```

**How agent prompts work:**

| Prompt type | Example | Behaviour |
|---|---|---|
| Question | `"what is XSS?"` | Direct AI answer, no confirmation |
| Action | `"scan for SQL injection"` | Shows banner, asks yes/no first |
| Action (confirmed) | `yes` | Executes using skill + tools, writes full results to the agent file |

Every response — question or action — is saved to `agents/<name>.md` so you always have a full history.

**The agent file** (`agents/rex.md`) contains:
- Header: created time, target, last chat time, total characters
- Full conversation log with timestamps

Agent files are kept private and not shared when you push to GitHub.

---

## Skills and Tools

```bash
stelarstrike --skills   # list skills
stelarstrike --tools    # list tools
```

**Skills** are security knowledge bases agents use when executing actions:

| Skill | What it covers |
|---|---|
| SQL Injection | UNION-based, blind, error-based, time-based across MySQL / PostgreSQL / MSSQL / SQLite |
| XSS Injection | Reflected, stored, DOM — WAF bypass, CSP bypass, polyglots |
| File Inclusion | LFI / RFI, PHP wrappers, LFI-to-RCE |
| Cross-Site Request Forgery | CSRF bypass techniques |
| Insecure Direct Object References | IDOR enumeration and exploitation |
| Web Cache Deception | Cache poisoning and deception |

**Tools** are referenced by agents for recommendations (SQLMap, Nmap, Burp Suite, etc.).

---

## Plugins

```bash
stelarstrike plugins
```

| ID | Name | Severity |
|---|---|---|
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
deactivate              # exit virtual environment first
rm -rf stelarstrike/    # delete the entire project folder
```

If you installed globally (without a virtual environment):
```bash
pip uninstall stelarstrike -y
```

---

## Updating

```bash
git pull origin main
pip install -e ".[dev]"
```

If `git pull` fails because you edited a file locally:
```bash
git stash          # saves your local edits temporarily
git pull origin main
git stash pop      # brings your edits back
```

After updating, check if `config/config.example.yaml` or `.env.example` have new fields by comparing them to your own files:
```bash
diff .env .env.example
diff config/config.yaml config/config.example.yaml
```
