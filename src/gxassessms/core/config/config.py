"""Engagement configuration -- loaded from YAML, validated, then read-only.

Separate from domain models because config has a different lifecycle:
loaded once at pipeline start, never mutated during execution.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from gxassessms.core.contracts.errors import ConfigError


class ToolConfig(BaseModel):
    """Per-tool configuration."""

    enabled: bool = False
    modules: list[str] = Field(default_factory=list)
    timeout: int = 600
    extra_args: dict[str, Any] = Field(default_factory=dict)


class AuthConfig(BaseModel):
    """Authentication settings."""

    method: str  # "client_credential", "device_code", "interactive"
    tenant_id: str
    client_id: str
    client_secret_env: str = ""
    certificate_path: str | None = None


class EngagementConfig(BaseModel):
    """Root engagement configuration."""

    client_name: str
    tenant_id: str
    auth: AuthConfig
    tools: dict[str, ToolConfig]
    max_parallel: int = 4
    report_formats: list[str] = Field(default_factory=lambda: ["docx"])
    report_theme: str = "basic"
    report_logo_path: str | None = None
    qa_model: str = "claude-sonnet-4-6"
    qa_token_budget: int = 100000


def load_config(path: Path) -> EngagementConfig:
    """Load and validate an engagement config from a YAML file.

    Raises ConfigError on file not found, invalid YAML, or validation failure.
    """
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in {path}: {e}") from e

    if not isinstance(raw, dict):
        raise ConfigError(f"Config file must be a YAML mapping, got {type(raw).__name__}")

    try:
        return _parse_raw_config(raw)
    except ConfigError:
        raise
    except (ValueError, TypeError, KeyError) as e:
        raise ConfigError(f"Config validation failed: {e}") from e


def _parse_raw_config(raw: dict[str, Any]) -> EngagementConfig:
    """Parse raw YAML dict into EngagementConfig."""
    client = raw.get("client", {})
    auth_raw = raw.get("auth", {})
    tools_raw = raw.get("tools", {})
    report_raw = raw.get("report", {})
    pipeline_raw = raw.get("pipeline", {})

    tools = {
        name: ToolConfig(**cfg) if isinstance(cfg, dict) else ToolConfig(enabled=bool(cfg))
        for name, cfg in tools_raw.items()
    }

    auth = AuthConfig(**auth_raw)

    return EngagementConfig(
        client_name=client.get("name", ""),
        tenant_id=client.get("tenant_id", ""),
        auth=auth,
        tools=tools,
        max_parallel=pipeline_raw.get("max_parallel", 4),
        report_formats=report_raw.get("formats", ["docx"]),
        report_theme=report_raw.get("theme", "basic"),
        report_logo_path=report_raw.get("logo_path"),
        qa_model=pipeline_raw.get("qa_model", "claude-sonnet-4-6"),
        qa_token_budget=pipeline_raw.get("qa_token_budget", 100000),
    )


def validate_config(config: EngagementConfig) -> tuple[list[str], list[str]]:
    """Validate an engagement config. Returns (errors, warnings).

    Errors are blocking. Warnings are advisory.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not config.tenant_id:
        errors.append("tenant_id is required")

    if not config.client_name:
        errors.append("client_name is required")

    if not config.auth.tenant_id:
        errors.append("auth.tenant_id is required")

    if not config.auth.client_id:
        errors.append("auth.client_id is required")

    enabled_tools = [name for name, tc in config.tools.items() if tc.enabled]
    if not enabled_tools:
        warnings.append("No tools are enabled -- pipeline will produce no findings")

    return errors, warnings
