"""Tests for the v2 agent system."""

from __future__ import annotations

import tempfile
from pathlib import Path

from stelarstrike.core.agent import (
    _is_action_prompt,
    _detect_relevant_skill,
    create_agent,
    delete_agent,
    list_agents,
    parse_header,
    validate_name,
)


# ── name validation ────────────────────────────────────────────────────────

def test_valid_name_2_chars():
    assert validate_name("ab") is None


def test_valid_name_7_chars():
    assert validate_name("alpha01") is None


def test_valid_name_mixed_case():
    assert validate_name("Rex99") is None


def test_name_too_short():
    err = validate_name("a")
    assert err is not None
    assert "short" in err.lower() or "2" in err


def test_name_too_long():
    err = validate_name("toolongname")
    assert err is not None
    assert "long" in err.lower() or "7" in err


def test_name_invalid_chars_hyphen():
    err = validate_name("my-bot")
    assert err is not None


def test_name_invalid_chars_space():
    err = validate_name("my bot")
    assert err is not None


def test_name_reserved_stelarstrike():
    # "stelarstrike" is >7 chars so fails length check first,
    # but "agent" is exactly 5 chars — must be caught by reserved check
    err = validate_name("agent")
    assert err is not None
    assert "reserved" in err.lower() or "allowed" in err.lower()


def test_name_reserved_case_insensitive():
    err = validate_name("Agent")
    assert err is not None


def test_name_numeric_only():
    assert validate_name("007") is None


# ── create / delete / list ─────────────────────────────────────────────────

def _run_in_tmp(fn):
    """Run a function with agents/ pointing at a temp directory."""
    with tempfile.TemporaryDirectory() as tmp:
        import stelarstrike.core.agent as agent_mod
        original = agent_mod.AGENTS_DIR
        agent_mod.AGENTS_DIR = Path(tmp) / "agents"
        try:
            return fn(Path(tmp))
        finally:
            agent_mod.AGENTS_DIR = original


def test_create_agent_success():
    def run(tmp):
        msg = create_agent("rex", "http://target.test/")
        assert "created" in msg.lower()
        assert (agent_mod.AGENTS_DIR / "rex.md").exists()

    import stelarstrike.core.agent as agent_mod
    _run_in_tmp(run)


def test_create_agent_already_exists():
    def run(tmp):
        create_agent("rex", "http://target.test/")
        msg = create_agent("rex", "http://target.test/")
        assert msg == "The agent exists"

    _run_in_tmp(run)


def test_create_agent_invalid_name():
    def run(tmp):
        msg = create_agent("x", "http://target.test/")
        assert "Error" in msg

    _run_in_tmp(run)


def test_delete_agent_success():
    def run(tmp):
        create_agent("del01", "http://target.test/")
        msg = delete_agent("del01")
        assert "deleted" in msg.lower()
        assert not (agent_mod.AGENTS_DIR / "del01.md").exists()

    import stelarstrike.core.agent as agent_mod
    _run_in_tmp(run)


def test_delete_agent_not_found():
    def run(tmp):
        msg = delete_agent("ghost")
        assert "Error" in msg or "does not exist" in msg.lower()

    _run_in_tmp(run)


def test_list_agents_empty():
    def run(tmp):
        rows = list_agents()
        assert rows == []

    _run_in_tmp(run)


def test_list_agents_shows_created():
    def run(tmp):
        create_agent("alpha", "http://alpha.test/")
        create_agent("beta7", "http://beta.test/")
        rows = list_agents()
        names = [r["name"] for r in rows]
        assert "alpha" in names
        assert "beta7" in names

    _run_in_tmp(run)


# ── .md header parsing ─────────────────────────────────────────────────────

def test_header_parsed_correctly():
    with tempfile.NamedTemporaryFile(suffix=".md", mode="w", delete=False) as f:
        f.write("---\ncreated: 2026-01-01T00:00:00\ntarget: http://x.test/\nstatus: idle\n---\n\nbody")
        path = Path(f.name)
    header = parse_header(path)
    assert header["created"] == "2026-01-01T00:00:00"
    assert header["target"] == "http://x.test/"
    assert header["status"] == "idle"
    path.unlink()


def test_header_missing_returns_empty():
    with tempfile.NamedTemporaryFile(suffix=".md", mode="w", delete=False) as f:
        f.write("No header here, just body text")
        path = Path(f.name)
    header = parse_header(path)
    assert header == {}
    path.unlink()


# ── action detection ──────────────────────────────────────────────────────

def test_action_detected_scan():
    assert _is_action_prompt("please scan the login page") is True


def test_action_detected_do():
    assert _is_action_prompt("do a SQL injection test") is True


def test_action_detected_test():
    assert _is_action_prompt("test the target for XSS") is True


def test_no_action_general_question():
    assert _is_action_prompt("what is SQL injection?") is False


def test_no_action_greeting():
    assert _is_action_prompt("hello, how are you?") is False


# ── skill detection ───────────────────────────────────────────────────────

def test_skill_detected_sqli():
    skill = _detect_relevant_skill("scan for sql injection vulnerabilities")
    assert skill == "SQL Injection"


def test_skill_detected_xss():
    skill = _detect_relevant_skill("test for xss")
    assert skill == "XSS Injection"


def test_skill_detected_csrf():
    skill = _detect_relevant_skill("check for csrf vulnerabilities")
    assert skill == "Cross-Site Request Forgery"


def test_skill_none_for_generic():
    skill = _detect_relevant_skill("what is the weather today")
    assert skill is None
