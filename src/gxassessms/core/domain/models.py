"""Pydantic domain models for the GxAssessMS assessment pipeline.

All models use UTC datetimes (via datetime_utils). Models are created
during pipeline execution. Config models (separate module) are loaded
once and frozen.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from gxassessms.core.config.datetime_utils import ensure_utc
from gxassessms.core.domain.constants import (
    ConfidenceProvenance,
    FileEncoding,
    RemediationPhaseName,
)
from gxassessms.core.domain.enums import (
    AdapterRunStatus,
    Category,
    CoverageStatus,
    FindingStatus,
    Severity,
    ToolSource,
)

_ENV_CREDENTIAL_REF_RE: re.Pattern[str] = re.compile(r"^[_A-Z][_A-Z0-9]*$")
_PROVIDER_NAME_RE: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9_]*$")
_PROVIDER_KEY_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


def _reject_bool(v: Any) -> Any:
    if isinstance(v, bool):
        raise ValueError("numeric fields must not be booleans")
    return v


def _is_valid_credential_ref(value: str) -> bool:
    if not value or any(char.isspace() for char in value):
        return False

    if _ENV_CREDENTIAL_REF_RE.fullmatch(value):
        return True

    provider, separator, key = value.partition(":")
    if not separator:
        return False

    if provider == "env":
        return bool(_ENV_CREDENTIAL_REF_RE.fullmatch(key))

    if ":" in key:
        return False

    return bool(_PROVIDER_NAME_RE.fullmatch(provider) and _PROVIDER_KEY_RE.fullmatch(key))


def _validate_credential_refs(refs: dict[str, str]) -> dict[str, str]:
    if not refs:
        return refs

    for ref_name, ref_value in refs.items():
        if _is_valid_credential_ref(ref_value):
            continue
        raise ValueError(
            f"credential_refs[{ref_name!r}] must be a lookup reference like "
            "'GX_CLIENT_SECRET', 'env:GX_CLIENT_SECRET', or "
            "'key_vault:tenant/prod/client-secret'; raw secret values are not allowed"
        )

    return refs


class SourceEvidence(BaseModel):
    """Raw tool output for a single check."""

    tool: ToolSource
    check_id: str
    raw_data: dict[str, Any]


class ToolObservation(BaseModel):
    """Tool-specific parsed output, not yet normalized.

    Contains the tool's native severity, status, and check ID exactly as
    reported. One adapter parse = one list of ToolObservations. This layer
    isolates tool output format changes from domain normalization.
    """

    observation_id: str
    tool: ToolSource
    native_check_id: str
    title: str
    native_severity: str
    native_status: str
    description: str
    raw_data: dict[str, Any] = Field(default_factory=dict)
    benchmark_refs: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """Normalized finding after applying normalization policy.

    Severity, category, and dedup keys are domain values, not tool-native.
    """

    observation_id: str
    native_check_id: str
    finding_key: str
    tool: ToolSource
    title: str
    severity: Severity
    status: FindingStatus
    category: Category
    description: str
    dedup_keys: list[str]
    benchmark_refs: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("dedup_keys")
    @classmethod
    def dedup_keys_must_be_nonempty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("dedup_keys must contain at least one key")
        return v


class ConfidenceScore(BaseModel):
    """Scored confidence model attached to each ConsolidatedFinding."""

    evidence_strength: float = Field(ge=0.0, le=1.0)
    corroborating_tools: int = Field(ge=0)
    data_freshness: float = Field(ge=0.0, le=1.0)
    provenance: ConfidenceProvenance
    overall: float = Field(ge=0.0, le=1.0)

    @field_validator(
        "evidence_strength", "data_freshness", "overall", "corroborating_tools", mode="before"
    )
    @classmethod
    def reject_bool_numerics(cls, v: Any) -> Any:
        return _reject_bool(v)


class ConsolidatedFinding(BaseModel):
    """Post-dedup, enriched, cross-validated finding."""

    finding_instance_id: str
    finding_key: str
    title: str
    severity: Severity
    status: FindingStatus
    category: Category
    description: str
    sources: list[SourceEvidence]
    confidence: ConfidenceScore
    benchmark_refs: list[str] = Field(default_factory=list)
    root_cause: str | None = None
    remediation: str | None = None
    narrative: str | None = None

    @field_validator("sources")
    @classmethod
    def sources_must_be_nonempty(cls, v: list[SourceEvidence]) -> list[SourceEvidence]:
        if not v:
            raise ValueError("sources must contain at least one evidence record")
        return v


class CoverageRecord(BaseModel):
    """Per-control assessment status from an adapter."""

    control_id: str
    tool: ToolSource
    status: CoverageStatus
    reason: str | None = None


class RawToolOutput(BaseModel):
    """Serializable container for raw tool output (enables replay)."""

    tool: ToolSource
    schema_version: str
    timestamp: datetime
    file_manifest: dict[str, FileEncoding]
    execution_metadata: dict[str, Any]

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_utc(cls, v: datetime) -> datetime:
        return ensure_utc(v)


class AdapterResult(BaseModel):
    """Wrapper returned by the adapter runner."""

    adapter_name: str
    status: AdapterRunStatus
    raw_output: RawToolOutput | None = None
    error: str | None = None
    duration_seconds: float = Field(ge=0)

    @model_validator(mode="after")
    def status_payload_consistent(self) -> AdapterResult:
        """Enforce that status matches the presence of raw_output/error."""
        if self.status == AdapterRunStatus.SUCCESS:
            if self.raw_output is None:
                raise ValueError("SUCCESS status requires raw_output")
            if self.error is not None:
                raise ValueError("SUCCESS status must not carry an error")
        elif self.status in (AdapterRunStatus.FAILED, AdapterRunStatus.TIMEOUT):
            if not self.error:
                raise ValueError(f"{self.status} status requires error message")
        elif self.status == AdapterRunStatus.SKIPPED:
            if self.raw_output is not None:
                raise ValueError("SKIPPED status must not carry raw_output")
        return self


class ToolRunResult(BaseModel):
    """Execution metadata for a single tool run."""

    tool: ToolSource
    started_at: datetime
    completed_at: datetime
    status: AdapterRunStatus
    finding_count: int = Field(ge=0)
    error: str | None = None

    @field_validator("finding_count", mode="before")
    @classmethod
    def reject_bool_finding_count(cls, v: Any) -> Any:
        return _reject_bool(v)

    @field_validator("started_at", "completed_at")
    @classmethod
    def timestamps_must_be_utc(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    @model_validator(mode="after")
    def validate_run_invariants(self) -> ToolRunResult:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must be >= started_at")
        if self.status in (AdapterRunStatus.FAILED, AdapterRunStatus.TIMEOUT) and not self.error:
            raise ValueError(f"{self.status} status requires error message")
        if self.status == AdapterRunStatus.SUCCESS and self.error is not None:
            raise ValueError("SUCCESS status must not carry an error")
        return self


class RemediationPhase(BaseModel):
    """Phased roadmap entry."""

    phase: RemediationPhaseName
    title: str
    description: str
    findings: list[str] = Field(default_factory=list)  # finding_instance_ids
    priority: int = 0


class ReportKeyStats(BaseModel):
    """Summary statistics for report header."""

    total_findings: int = Field(ge=0)
    critical_count: int = Field(ge=0)
    high_count: int = Field(ge=0)
    medium_count: int = Field(ge=0)
    low_count: int = Field(ge=0)
    info_count: int = Field(ge=0)
    tools_run: int = Field(ge=0)
    tools_failed: int = Field(ge=0)
    controls_assessed: int = Field(ge=0)
    controls_not_assessed: int = Field(ge=0)

    @field_validator("*", mode="before")
    @classmethod
    def reject_bool_counters(cls, v: Any) -> Any:
        return _reject_bool(v)


class ReportPayload(BaseModel):
    """JSON contract between Python pipeline and Node.js renderers.

    The dict[str, Any] fields are intentional -- the JSON schema is shared
    across the Python/Node.js language boundary for report generation.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    engagement_id: str
    tenant_name: str
    assessment_date: str
    tool_sources: list[str]
    findings: list[dict[str, Any]]
    coverage: list[dict[str, Any]]
    narratives: dict[str, str | None]
    metadata: dict[str, Any]


class AuthContext(BaseModel):
    """Authentication state from adapter's authenticate() method.

    ``token`` may hold secret material. ``credential_refs`` must contain only
    provider lookup identifiers that are resolved later, never raw secrets.
    """

    # Hide raw values in default ValidationError string rendering. Structured
    # errors still retain the original input in Pydantic.
    model_config = ConfigDict(hide_input_in_errors=True)

    token: SecretStr | None = None
    credential_refs: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "CredentialProvider lookup refs only, such as env var names or "
            "provider-qualified aliases. Raw secret values are not allowed."
        ),
    )
    expires_at: datetime | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("credential_refs")
    @classmethod
    def credential_refs_must_be_lookup_refs(cls, v: dict[str, str]) -> dict[str, str]:
        return _validate_credential_refs(v)

    @field_validator("expires_at")
    @classmethod
    def expires_at_must_be_utc(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return v
        return ensure_utc(v)
