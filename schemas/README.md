# Alternative Schemas

Schemas are **generic pattern files** describing a *category* of web application
(e.g. "Flask + PostgreSQL web app", "Django REST Framework API", "Spring Boot + MySQL").
They are NOT named after specific targets.

When StelarStrike recognises a target as matching a known pattern, it:
1. Adds the pattern's known endpoint list to the scan queue (alongside discovery)
2. Guides the extractor with likely column positions to try first
3. Runs category-specific extra checks (e.g. Werkzeug debug console for Flask apps)

Extraction and enumeration still run fully — schemas are hints, not shortcuts.

---

## Schema file format

```yaml
name: "Short descriptive pattern name (e.g. Flask + PostgreSQL Web App)"
description: "What category of app this covers."

# Fingerprints — match if ANY ONE of these matches (OR logic).
# Use generic indicators, never target-specific strings.
fingerprints:
  - header_contains: "Werkzeug"        # Flask development server
  - header_contains: "python"           # generic Python backend
  - response_contains: "X-Powered-By: Flask"

# Common endpoints to probe in this category.
# These are ADDED to the discovery queue, not replacing it.
probe_endpoints:
  - path: "/login"
    method: "POST"
    body_types: ["json", "form"]
    injectable_fields: ["username", "email", "user"]
  - path: "/api/auth"
    method: "POST"
    body_types: ["json"]
  - path: "/admin"
    method: "GET"

# SQLi category hints — guides (not replaces) enumeration
sqli:
  likely_db: "postgresql"            # default db_type assumption
  try_positions_first: [1, 0, 2]    # positions to try before exhaustive search
  col_count_hint: 10                 # typical col count for this stack (starting point)

# Extra checks specific to this category
extra_checks:
  - name: "Werkzeug Debug Console"
    path: "/console"
    indicator: "Werkzeug Debugger"
    severity: "critical"
  - name: "Flask Debug Traceback"
    indicator: "Traceback (most recent call last)"
    severity: "high"
```

## How to add a schema from a writeup

1. Complete a scan on any target, or read a writeup/Big Pickle output
2. Identify the PATTERN (Flask? Django? Spring Boot? What DB?)
3. Paste to Claude: *"Extract a generic StelarStrike schema YAML for this app pattern.
   Do NOT name it after the specific target."*
4. Save as `schemas/<pattern-name>.yaml`

## What NOT to include

- Target-specific strings like app/company names in fingerprints
- Hardcoded col_count / reflected_col (these vary per query, not per stack)
- Extracted data (passwords, PII, tokens)
