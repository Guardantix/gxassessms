"""Engagement configuration -- loaded from YAML, validated, then read-only.

Separate from domain models because config has a different lifecycle:
loaded once at pipeline start, never mutated during execution.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic import ValidationError as PydanticValidationError

from gxassessms.core.contracts.errors import ConfigError, ConfigValidationError
from gxassessms.core.contracts.verification import ModulePolicyOverride
from gxassessms.core.domain.constants import AuthMethod


class ToolConfig(BaseModel):
    """Per-tool configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = False
    output_dir: str = ""
    controls_dir: str = ""
    script_dir: str = ""
    modules: list[str] = Field(default_factory=list)
    timeout: int | None = Field(default=None, gt=0)
    extra_args: list[str] = Field(default_factory=list)
    module_policy_override: ModulePolicyOverride | None = None

    @field_validator("module_policy_override", mode="before")
    @classmethod
    def parse_module_policy_override(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, dict):
            raw: dict[str, Any] = cast(dict[str, Any], v)
            pinned: Any = raw.get("pinned_package_hashes")
            if pinned is not None:
                raw["pinned_package_hashes"] = frozenset(pinned)
            return ModulePolicyOverride(**raw)
        return v

    @field_validator("enabled", mode="before")
    @classmethod
    def reject_non_bool_enabled(cls, v: Any) -> Any:
        if not isinstance(v, bool):
            raise ValueError(f"enabled must be a boolean, got {type(v).__name__}")
        return v

    @field_validator("timeout", mode="before")
    @classmethod
    def reject_bool_timeout(cls, v: Any) -> Any:
        if isinstance(v, bool):
            raise ValueError("timeout must be an integer, not a boolean")
        return v


class AuthConfig(BaseModel):
    """Authentication settings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    method: AuthMethod
    tenant_id: str
    client_id: str
    client_secret_env: str = ""
    certificate_path: str | None = None


class EngagementConfig(BaseModel):
    """Root engagement configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    client_name: str
    tenant_id: str
    subscription_id: str = ""
    auth: AuthConfig
    tools: dict[str, ToolConfig]
    max_parallel: int = Field(default=4, gt=0)
    report_formats: list[str] = Field(default_factory=lambda: ["docx"])
    report_theme: str = "basic"
    report_logo_path: str | None = None
    qa_model: str = "claude-sonnet-4-6"
    qa_token_budget: int = Field(default=100000, gt=0)

    @field_validator("max_parallel", "qa_token_budget", mode="before")
    @classmethod
    def reject_bool_integers(cls, v: Any) -> Any:
        if isinstance(v, bool):
            raise ValueError("value must be an integer, not a boolean")
        return v


def load_config(path: Path) -> EngagementConfig:
    """Load and validate an engagement config from a YAML file.

    Raises ConfigError on file not found, invalid YAML, or structural failure.
    Raises ConfigValidationError on blocking validation errors (empty required
    fields, misspelled config keys, etc.).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise ConfigError(f"Config file not found: {path}") from e
    except UnicodeDecodeError as e:
        raise ConfigError(f"Config file {path} is not valid UTF-8: {e}") from e
    except OSError as e:
        raise ConfigError(f"Cannot read config file {path}: {e}") from e

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in {path}: {e}") from e

    if not isinstance(raw, dict):
        raise ConfigError(f"Config file must be a YAML mapping, got {type(raw).__name__}")

    try:
        config = _parse_raw_config(cast(dict[str, Any], raw))
    except ConfigError:
        raise
    except PydanticValidationError as e:
        raise ConfigError(f"Config validation failed: {e}") from e

    errors, warnings = validate_config(config)
    if errors:
        raise ConfigValidationError(
            message="Config validation failed: " + "; ".join(errors),
            errors=errors,
            warnings=warnings,
        )

    return config


_KNOWN_SECTIONS = frozenset({"client", "auth", "tools", "report", "pipeline"})
_KNOWN_CLIENT_KEYS = frozenset({"name", "tenant_id", "subscription_id"})
_KNOWN_REPORT_KEYS = frozenset({"formats", "theme", "logo_path"})
_KNOWN_PIPELINE_KEYS = frozenset({"max_parallel", "qa_model", "qa_token_budget"})


def _parse_raw_config(raw: dict[str, Any]) -> EngagementConfig:
    """Parse raw YAML dict into EngagementConfig."""
    unknown = set(raw.keys()) - _KNOWN_SECTIONS
    if unknown:
        raise ConfigError(f"Unknown config sections: {', '.join(sorted(str(k) for k in unknown))}")

    # Required sections
    for key in ("client", "auth"):
        if key not in raw:
            raise ConfigError(f"Missing required config section: '{key}'")
        if not isinstance(raw[key], dict):
            raise ConfigError(
                f"Config section '{key}' must be a mapping, got {type(raw[key]).__name__}"
            )

    # Optional sections -- must be dicts if present
    for key in ("tools", "report", "pipeline"):
        if key in raw and not isinstance(raw[key], dict):
            raise ConfigError(
                f"Config section '{key}' must be a mapping, got {type(raw[key]).__name__}"
            )

    client: dict[str, Any] = raw["client"]
    auth_raw: dict[str, Any] = raw["auth"]
    tools_raw: dict[str, Any] = raw.get("tools", {})
    report_raw: dict[str, Any] = raw.get("report", {})
    pipeline_raw: dict[str, Any] = raw.get("pipeline", {})

    # Reject unknown keys in nested sections
    for section_name, section_dict, known_keys in (
        ("client", client, _KNOWN_CLIENT_KEYS),
        ("report", report_raw, _KNOWN_REPORT_KEYS),
        ("pipeline", pipeline_raw, _KNOWN_PIPELINE_KEYS),
    ):
        bad = set(section_dict.keys()) - known_keys
        if bad:
            raise ConfigError(
                f"Unknown keys in '{section_name}': {', '.join(sorted(str(k) for k in bad))}"
            )

    tools: dict[str, ToolConfig] = {}
    for name, cfg in tools_raw.items():
        if isinstance(cfg, dict):
            tools[name] = ToolConfig(**cast(dict[str, Any], cfg))
        elif isinstance(cfg, bool):
            tools[name] = ToolConfig(enabled=cfg)
        else:
            raise ConfigError(
                f"Tool '{name}' must be a mapping or boolean, got {type(cfg).__name__}: {cfg!r}"
            )

    auth = AuthConfig(**auth_raw)

    return EngagementConfig(
        client_name=client.get("name", ""),
        tenant_id=client.get("tenant_id", ""),
        subscription_id=client.get("subscription_id", ""),
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

    if (
        config.auth.method == "client_credential"
        and not config.auth.client_secret_env
        and not config.auth.certificate_path
    ):
        errors.append(
            "auth: client_credential method requires client_secret_env or certificate_path"
        )

    if config.auth.method in ("device_code", "interactive"):
        if config.auth.client_secret_env:
            warnings.append(f"auth: {config.auth.method} method ignores client_secret_env")
        if config.auth.certificate_path:
            warnings.append(f"auth: {config.auth.method} method ignores certificate_path")

    if config.tenant_id and config.auth.tenant_id and config.tenant_id != config.auth.tenant_id:
        errors.append(
            "tenant_id and auth.tenant_id must be the same value; "
            "cross-tenant delegation is not currently supported"
        )

    if not any(tc.enabled for tc in config.tools.values()):
        warnings.append("No tools are enabled -- pipeline will produce no findings")

    return errors, warnings
