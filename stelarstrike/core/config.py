"""
Configuration loader for StelarStrike.

Loads config/config.yaml (or the path in STELAR_CONFIG_PATH), resolves
${VAR_NAME} / ${VAR_NAME:-default} placeholders against environment
variables (populated from .env via python-dotenv), and exposes a typed
Settings object the rest of the app consumes.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

_VAR_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)(:-([^}]*))?\}")


def _interpolate(value: Any) -> Any:
    """Recursively replace ${VAR} / ${VAR:-default} with env values."""
    if isinstance(value, str):
        def repl(match: re.Match) -> str:
            var_name, _, default = match.groups()
            return os.environ.get(var_name, default if default is not None else "")

        return _VAR_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


class HttpConfig(BaseModel):
    timeout_seconds: float = 15
    max_concurrency: int = 10
    user_agent: str = "StelarStrike/0.1"
    follow_redirects: bool = True
    verify_tls: bool = True
    extra_headers: dict[str, str] = Field(default_factory=dict)


class PluginConfig(BaseModel):
    enabled: bool = True
    options: dict[str, Any] = Field(default_factory=dict)


class AIConfig(BaseModel):
    enabled: bool = True
    provider: str = "opencode/big-pickle"
    max_tokens: int = 2000
    temperature: float = 0.2
    roles: dict[str, bool] = Field(default_factory=dict)


class EngagementConfig(BaseModel):
    name: str = "default"
    scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    allow_active_payloads: bool = False


class DiscoveryConfig(BaseModel):
    enabled: bool = True
    max_urls: int = 10
    max_depth: int = 1
    synthetic_params: list[str] = Field(
        default_factory=lambda: ["id", "page", "category", "search", "q", "user_id"]
    )


class Settings(BaseModel):
    project_name: str = "StelarStrike"
    report_dir: str = "reports"
    log_level: str = "INFO"
    engagement: EngagementConfig = Field(default_factory=EngagementConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    http: HttpConfig = Field(default_factory=HttpConfig)
    plugins: dict[str, PluginConfig] = Field(default_factory=dict)
    ai: AIConfig = Field(default_factory=AIConfig)
    reporting: dict[str, Any] = Field(default_factory=dict)
    notifications: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)


def load_settings(config_path: str | Path | None = None) -> Settings:
    """Load .env then config.yaml, interpolate env vars, return a Settings object."""
    load_dotenv(override=False)

    path = Path(config_path or os.environ.get("STELAR_CONFIG_PATH", "config/config.yaml"))
    if not path.exists():
        example = path.with_name(path.stem + ".example" + path.suffix)
        raise FileNotFoundError(
            f"Config file not found at '{path}'. "
            f"Copy '{example}' to '{path}' and edit it, "
            f"or set STELAR_CONFIG_PATH to point elsewhere."
        )

    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    raw = _interpolate(raw)

    plugins_raw = raw.get("plugins", {}) or {}
    plugins = {
        name: PluginConfig(enabled=bool(cfg.get("enabled", True)), options=cfg)
        for name, cfg in plugins_raw.items()
    }

    settings = Settings(
        project_name=raw.get("project", {}).get("name", "StelarStrike"),
        report_dir=raw.get("project", {}).get("report_dir", "reports"),
        log_level=raw.get("project", {}).get("log_level", "INFO"),
        engagement=EngagementConfig(**raw.get("engagement", {})),
        discovery=DiscoveryConfig(**raw.get("discovery", {})),
        http=HttpConfig(**raw.get("http", {})),
        plugins=plugins,
        ai=AIConfig(**raw.get("ai", {})),
        reporting=raw.get("reporting", {}),
        notifications=raw.get("notifications", {}),
        raw=raw,
    )
    return settings
