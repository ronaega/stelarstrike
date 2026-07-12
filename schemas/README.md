# Alternative Schemas

A schema is a YAML file that encodes what StelarStrike learned from a previous
scan (or a writeup) about a specific **type** of target — its stack, its
injectable endpoints, the UNION column count, the reflected column position,
and any bypass payloads that were confirmed working.

When StelarStrike recognises a target as matching a known schema, it skips
slow discovery and column-count enumeration and goes straight to the known
attack pattern. This saves 20–100+ HTTP requests per scan and dramatically
reduces AI triage tokens spent on already-understood findings.

---

## Schema file format

```yaml
# schemas/<descriptive-name>.yaml

name: "Short descriptive name"
description: "What this schema is for and where it came from."
source: "e.g. MerdekaBank Lab — Merdeka Siber Batch 27"

# ---  Fingerprinting  ---
# StelarStrike fetches the target root and checks these.
# A target matches if ALL fingerprints in the list are satisfied.
fingerprints:
  - response_contains: "MerdekaBank"     # string in the HTML body
  - header_contains: "Werkzeug"          # string in any response header
  - status_code: 200                     # HTTP status of the root URL
  # (all three fields are optional — include only the ones you know)

# ---  Stack info (informational only, used in the report) ---
stack:
  language: "Python"
  framework: "Flask"
  db: "postgresql"
  db_version: "13.23"

# ---  Confirmed injection points  ---
# Each entry is one injectable endpoint + field combination.
injections:
  - id: "login_username"
    endpoint: "/login"
    method: "POST"
    body_type: "json"          # json | form | query
    field: "username"
    injection_type: "sqli"
    sqli:
      confirmed_techniques: ["error-based", "auth-bypass", "union"]
      col_count: 10            # how many columns the UNION SELECT needs
      reflected_col: 1         # 0-indexed position of the column that echoes back
      inject_prefix: "'"       # string (') or numeric ( ) context
      db_type: "postgresql"
      bypass_payload: "' OR 1=1-- -"
      union_comment: "-- -"
    evidence: "POST /login {username: \"' OR 1=1-- -\"} → JWT token returned"

# ---  Known endpoints (auth-required ones noted so the scan doesn't waste time) ---
endpoints:
  - path: "/"
    method: "GET"
    auth_required: false
  - path: "/login"
    method: "POST"
    auth_required: false
    body_type: "json"
    fields: ["username", "password"]
  - path: "/transfer"
    method: "POST"
    auth_required: true      # requires Bearer token
    body_type: "json"
    fields: ["to_account", "amount"]

# ---  Additional findings from this target type (human reference only) ---
additional_findings:
  - title: "Flask Debug Mode / Werkzeug Debugger Exposed"
    severity: "high"
    url: "/console or stack traces on 500"
  - title: "Plaintext Passwords in users table"
    severity: "critical"
  - title: "Weak JWT Secret"
    severity: "high"
    note: "HS256, no expiry"
```

---

## How to create a schema from a writeup

When you have a writeup (from your own scan, from a classmate, or from Big Pickle):

1. Paste the writeup to Claude in your StelarStrike conversation.
2. Ask: *"Extract this as a StelarStrike schema YAML."*
3. Claude produces the YAML — save it as `schemas/<target-name>.yaml`.
4. Run `stelarstrike scan <target> --verbose` — it will say "Schema matched: <name>"
   and skip straight to the known attack pattern.

### What to include / exclude

Include:
- The endpoint that was vulnerable
- The HTTP method and body type (JSON vs form)
- The field name that was injectable
- The UNION column count and reflected column position
- The DB type
- Any bypass payloads that were confirmed working

Exclude:
- Actual extracted data (passwords, card numbers, PII) — schemas are shared knowledge, extracted data is not
- Anything specific to one user account or session

---

## How schemas reduce AI token usage

When a schema match is found, StelarStrike:
- Skips AI-assisted discovery ranking (the schema tells it where to look)
- Skips UNION column-count enumeration (already known)
- Can skip AI triage on findings that exactly match a schema's `additional_findings`
  (the severity and description are already written)

On a schema match, AI is still used for the report narrative — but the triage
call (which sends all raw findings to the LLM) is skipped if
`ai.roles.triage: true` and the findings are fully covered by the schema.
Set `ai.roles.triage: false` in `config.yaml` to skip it entirely for lab targets
you already understand.
