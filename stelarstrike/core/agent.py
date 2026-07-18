"""
Agent management for StelarStrike v2.

Each agent is a .md file in the agents/ directory. The file header
(between --- markers) tracks metadata; everything below is the chat log.
Header fields are NOT counted toward total_response_chars.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stelarstrike.utils.logger import get_logger

log = get_logger(__name__)

# ── paths ──────────────────────────────────────────────────────────────────
AGENTS_DIR = Path("agents")
SKILLS_DIR = Path(__file__).parent.parent / "skills"
TOOLS_FILE = Path(__file__).parent.parent / "tools" / "tools-list.json"

# ── constants ──────────────────────────────────────────────────────────────
RESERVED_NAMES = {"stelarstrike", "agent"}
NAME_PATTERN = re.compile(r"^[a-zA-Z0-9]{2,7}$")
OPENCODE_MODEL = "opencode/big-pickle"

# Explicit action verbs — always trigger action detection
ACTION_VERBS = {
    "do", "please", "scan", "test", "check", "find", "run", "exploit",
    "inject", "attack", "enumerate", "fuzz", "brute", "crawl", "probe",
    "bypass", "dump", "extract", "payload",
}

# Skill/technique terms — trigger action only when NOT in a question phrase
ACTION_KEYWORDS = ACTION_VERBS | {
    "sql", "xss", "sqli", "csrf", "idor", "lfi", "rfi", "ssrf", "jwt",
    "login", "register",
}

# Question openers — if prompt starts with these, only verb-based action detection applies
_QUESTION_OPENERS = {
    "what is", "what are", "what does", "what do",
    "how does", "how do", "how can", "how to",
    "explain", "tell me", "describe", "define",
    "why is", "why does", "can you explain", "can you tell",
}

SKILL_KEYWORDS: dict[str, str] = {
    "sql": "SQL Injection",
    "sqli": "SQL Injection",
    "injection": "SQL Injection",
    "xss": "XSS Injection",
    "cross-site scripting": "XSS Injection",
    "csrf": "Cross-Site Request Forgery",
    "forgery": "Cross-Site Request Forgery",
    "idor": "Insecure Direct Object References",
    "direct object": "Insecure Direct Object References",
    "lfi": "File Inclusion",
    "rfi": "File Inclusion",
    "file inclusion": "File Inclusion",
    "cache": "Web Cache Deception",
}


# ── name validation ────────────────────────────────────────────────────────

def validate_name(name: str) -> str | None:
    """Return an error message if invalid, None if valid."""
    if not NAME_PATTERN.match(name):
        if len(name) < 2:
            return f"Error: agent name '{name}' is too short (minimum 2 characters)."
        if len(name) > 7:
            return f"Error: agent name '{name}' is too long (maximum 7 characters)."
        return f"Error: agent name '{name}' must contain only letters and numbers."
    if name.lower() in RESERVED_NAMES:
        return f"Error: '{name}' is a reserved word and cannot be used as an agent name."
    return None


# ── agent file helpers ─────────────────────────────────────────────────────

def agent_path(name: str) -> Path:
    AGENTS_DIR.mkdir(exist_ok=True)
    return AGENTS_DIR / f"{name}.md"


def agent_exists(name: str) -> bool:
    return agent_path(name).exists()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _count_response_chars(content: str) -> int:
    """Count characters in Agent responses only (not headers, not User lines)."""
    total = 0
    in_agent_block = False
    for line in content.splitlines():
        if line.startswith("### Agent |"):
            in_agent_block = True
            continue
        if line.startswith("### ") and in_agent_block:
            in_agent_block = False
        if in_agent_block:
            total += len(line)
    return total


def parse_header(path: Path) -> dict[str, str]:
    """Parse YAML-like header between --- markers."""
    text = path.read_text(encoding="utf-8")
    header: dict[str, str] = {}
    if not text.startswith("---"):
        return header
    end = text.find("\n---\n", 3)
    if end == -1:
        return header
    for line in text[3:end].strip().splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            header[k.strip()] = v.strip()
    return header


def update_header(path: Path, updates: dict[str, str]) -> None:
    """Update specific header fields in-place without touching the body."""
    text = path.read_text(encoding="utf-8")
    end = text.find("\n---\n", 3)
    if end == -1:
        return
    header_block = text[3:end].strip()
    body = text[end + 5:]

    lines = header_block.splitlines()
    new_lines: list[str] = []
    updated_keys: set[str] = set()
    for line in lines:
        if ":" in line:
            k, _, _ = line.partition(":")
            k = k.strip()
            if k in updates:
                new_lines.append(f"{k}: {updates[k]}")
                updated_keys.add(k)
                continue
        new_lines.append(line)
    for k, v in updates.items():
        if k not in updated_keys:
            new_lines.append(f"{k}: {v}")

    path.write_text(f"---\n{chr(10).join(new_lines)}\n---\n{body}", encoding="utf-8")


# ── create / delete ────────────────────────────────────────────────────────

def create_agent(name: str, target: str) -> str:
    """Create a new agent file. Returns success or error message."""
    err = validate_name(name)
    if err:
        return err
    path = agent_path(name)
    if path.exists():
        return "The agent exists"
    now = _now()
    content = (
        f"---\n"
        f"created: {now}\n"
        f"target: {target}\n"
        f"last_chat: {now}\n"
        f"total_response_chars: 0\n"
        f"status: idle\n"
        f"---\n\n"
        f"# Agent: {name}\n"
        f"**Target:** {target}  \n"
        f"**Created:** {now}\n\n"
        f"---\n\n"
    )
    path.write_text(content, encoding="utf-8")
    return f"Agent '{name}' created. Target: {target}"


def delete_agent(name: str) -> str:
    """Delete an agent file. Returns success or error message."""
    err = validate_name(name)
    if err:
        return err
    path = agent_path(name)
    if not path.exists():
        return f"Error: agent '{name}' does not exist."
    path.unlink()
    return f"Agent '{name}' deleted."


def list_agents() -> list[dict[str, str]]:
    """Return a list of all agents with their metadata."""
    AGENTS_DIR.mkdir(exist_ok=True)
    agents = []
    for p in sorted(AGENTS_DIR.glob("*.md")):
        if p.name == ".gitkeep":
            continue
        header = parse_header(p)
        agents.append({
            "name": p.stem,
            "target": header.get("target", "—"),
            "created": header.get("created", "—"),
            "last_chat": header.get("last_chat", "—"),
            "total_response_chars": header.get("total_response_chars", "0"),
        })
    return agents


# ── skills / tools helpers ─────────────────────────────────────────────────

def list_skills() -> list[dict[str, str]]:
    skills = []
    for skill_dir in sorted(SKILLS_DIR.iterdir()):
        if not skill_dir.is_dir() or skill_dir.name.startswith("__"):
            continue
        readme = skill_dir / "README.md"
        desc = ""
        if readme.exists():
            for line in readme.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith(">") and len(line) > 10:
                    desc = line[:100]
                    break
        skills.append({"name": skill_dir.name, "description": desc or "Security testing skill"})
    return skills


def list_tools() -> list[dict[str, str]]:
    if not TOOLS_FILE.exists():
        return []
    data = json.loads(TOOLS_FILE.read_text(encoding="utf-8"))
    return [
        {"name": t["tools_name"], "description": t.get("description", ""), "category": t.get("category", "")}
        for t in data.get("tools", [])
    ]


def load_skill_content(skill_name: str) -> str:
    """Load the README.md of a skill for AI context."""
    skill_dir = SKILLS_DIR / skill_name
    readme = skill_dir / "README.md"
    if readme.exists():
        text = readme.read_text(encoding="utf-8", errors="ignore")
        return text[:4000]  # cap at 4000 chars to avoid huge prompts
    return ""


def _detect_relevant_skill(prompt: str) -> str | None:
    lower = prompt.lower()
    for kw, skill in SKILL_KEYWORDS.items():
        if kw in lower:
            return skill
    return None


# Word-boundary pattern for action verbs so "inject" never matches inside "injection"
_ACTION_VERB_RE = re.compile(
    r"\b(" + "|".join(re.escape(v) for v in sorted(ACTION_VERBS, key=len, reverse=True)) + r")\b"
)


def _is_action_prompt(prompt: str) -> bool:
    lower = prompt.lower().strip()
    # Question-phrased prompts: only trigger action when an explicit verb (whole word) is present
    is_question = any(lower.startswith(q) or f" {q} " in lower for q in _QUESTION_OPENERS)
    if is_question:
        return bool(_ACTION_VERB_RE.search(lower))
    # Non-question prompts: any action keyword triggers (substring match is fine here)
    return any(kw in lower for kw in ACTION_KEYWORDS)


# ── AI call via OpenCode ───────────────────────────────────────────────────

def _opencode_complete(system: str, user: str, model: str = OPENCODE_MODEL, timeout: int = 90) -> str:
    """Call opencode run and return the response text."""
    opencode = shutil.which("opencode")
    if not opencode:
        return "(OpenCode not installed. Run: curl -fsSL https://opencode.ai/install | bash)"

    prompt = f"{system}\n\n{user}" if system else user
    cmd = [opencode, "run", "--model", model, "--format", "json", prompt]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return _parse_opencode_output(result.stdout) or "(No response from AI)"
    except subprocess.TimeoutExpired:
        return "(OpenCode timed out)"
    except Exception as exc:  # noqa: BLE001
        return f"(OpenCode error: {exc})"


def _parse_opencode_output(ndjson: str) -> str:
    parts: list[str] = []
    for line in ndjson.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        etype = event.get("type", "")
        if etype == "error":
            log.debug(f"opencode error event: {event.get('error', {})}")
            return ""
        if etype in ("text", "content", "message_delta"):
            chunk = event.get("text") or event.get("content") or event.get("delta", {}).get("text", "")
            if chunk:
                parts.append(str(chunk))
        elif etype == "assistant":
            content = event.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
    return "".join(parts).strip()


# ── prompt handling ────────────────────────────────────────────────────────

def handle_prompt(agent_name: str, raw_prompt: str, model: str = OPENCODE_MODEL) -> tuple[str, str]:
    """
    Process a user prompt for an agent.
    Returns (response_text, response_type) where type is 'clarification' | 'answer' | 'action'.
    Appends the exchange to the agent's .md file.
    """
    path = agent_path(agent_name)
    header = parse_header(path)
    target = header.get("target", "unknown")
    status = header.get("status", "idle")
    now = _now()

    # Strip surrounding quotes if the user passed them literally
    prompt = raw_prompt.strip().strip('"').strip("'")

    # Check if we were waiting for confirmation and user said yes/no
    pending_action: str = header.get("pending_action", "")
    if status == "pending" and pending_action:
        affirmative = {"yes", "y", "ok", "sure", "go", "do it", "proceed", "yep", "yeah"}
        if prompt.lower().strip() in affirmative:
            response, rtype = _execute_action(pending_action, target, model)
        else:
            response = "Understood. Action cancelled. Let me know when you're ready."
            rtype = "answer"
        _append_to_file(path, now, prompt, response)
        _update_metadata(path, response, "idle", "")
        return response, rtype

    # Detect intent
    if _is_action_prompt(prompt):
        skill = _detect_relevant_skill(prompt)
        clarification = _build_clarification(prompt, skill, target)
        _append_to_file(path, now, prompt, clarification)
        _update_metadata(path, clarification, "pending", prompt)
        return clarification, "clarification"

    # General question → straight AI answer
    history = _load_recent_history(path, turns=6)
    system = (
        f"You are StelarStrike, an AI-powered offensive security agent. "
        f"Your assigned target is: {target}. "
        f"You are an expert penetration tester. "
        f"Be concise, accurate, and professional."
    )
    user_msg = f"Conversation history:\n{history}\n\nUser: {prompt}" if history else prompt
    response = _opencode_complete(system, user_msg, model)
    _append_to_file(path, now, prompt, response)
    _update_metadata(path, response, "idle", "")
    return response, "answer"


def _build_clarification(prompt: str, skill: str | None, target: str) -> str:
    skill_part = f" ({skill})" if skill else ""
    return (
        f"Do you want me to scan / test{skill_part} on the target **{target}**?\n\n"
        f"I detected an action intent in your request: *\"{prompt}\"*\n\n"
        f"Reply **yes** to proceed or **no** to cancel."
    )


def _execute_action(original_prompt: str, target: str, model: str) -> tuple[str, str]:
    """Execute an action using the relevant skill and tools."""
    skill_name = _detect_relevant_skill(original_prompt)
    skill_content = load_skill_content(skill_name) if skill_name else ""
    tools_context = _get_relevant_tools_context(original_prompt)

    system = (
        f"You are StelarStrike, an expert AI penetration testing agent.\n"
        f"Target: {target}\n"
        f"Your task: perform the requested security action professionally.\n"
        f"You have access to the following skill knowledge:\n\n"
        f"{skill_content}\n\n"
        f"Available tools context:\n{tools_context}\n\n"
        f"Instructions:\n"
        f"- Provide a detailed, professional penetration testing report\n"
        f"- Include: findings, evidence, severity, remediation\n"
        f"- Use markdown tables and headers for clarity\n"
        f"- Be specific and actionable\n"
        f"- If you cannot directly access the target, describe exactly what commands "
        f"to run and what to look for"
    )
    response = _opencode_complete(system, f"Perform the following action: {original_prompt}", model)
    return response, "action"


def _get_relevant_tools_context(prompt: str) -> str:
    if not TOOLS_FILE.exists():
        return ""
    data = json.loads(TOOLS_FILE.read_text(encoding="utf-8"))
    lower = prompt.lower()
    relevant = []
    for tool in data.get("tools", []):
        name = tool["tools_name"].lower()
        tags = [t.lower() for t in tool.get("tags", [])]
        if name in lower or any(t in lower for t in tags):
            relevant.append(f"- **{tool['tools_name']}**: {tool.get('description', '')}")
    if not relevant:
        return "No specific tools matched. Use general pentesting approach."
    return "\n".join(relevant[:5])


def _append_to_file(path: Path, timestamp: str, user_msg: str, agent_msg: str) -> None:
    entry = (
        f"### User | {timestamp}\n"
        f"{user_msg}\n\n"
        f"### Agent | {timestamp}\n"
        f"{agent_msg}\n\n"
        f"---\n\n"
    )
    with path.open("a", encoding="utf-8") as f:
        f.write(entry)


def _update_metadata(path: Path, response: str, status: str, pending_action: str) -> None:
    text = path.read_text(encoding="utf-8")
    current_chars = int(parse_header(path).get("total_response_chars", "0"))
    new_chars = current_chars + len(response)
    updates: dict[str, Any] = {
        "last_chat": _now(),
        "total_response_chars": str(new_chars),
        "status": status,
    }
    if pending_action:
        updates["pending_action"] = pending_action
    elif "pending_action" in text:
        updates["pending_action"] = ""
    update_header(path, updates)


def _load_recent_history(path: Path, turns: int = 6) -> str:
    text = path.read_text(encoding="utf-8")
    # Extract only the conversation blocks (after the second ---)
    body_start = text.find("\n---\n", 3)
    if body_start == -1:
        return ""
    body = text[body_start + 5:]
    # Find last N exchanges
    blocks = re.split(r"\n---\n", body)
    recent = [b.strip() for b in blocks if b.strip() and "### " in b]
    return "\n\n---\n\n".join(recent[-turns:])
