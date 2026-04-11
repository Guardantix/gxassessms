"""Typed exception hierarchy -- fail-closed, no silent fallbacks.

Every leaf exception carries enough context to diagnose without re-running.
Callers catch at the right granularity: `except GxAssessError` for any
GxAssessMS problem, `except AdapterError` for any adapter problem, or
`except CollectionError` for tool execution specifically.
"""

from typing import Any


class GxAssessError(Exception):
    """Base exception for all GxAssessMS errors."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


# ---------------------------------------------------------------------------
# Config errors
# ---------------------------------------------------------------------------


class ConfigError(GxAssessError):
    """Invalid YAML, missing fields, unknown adapter references."""


class ConfigValidationError(ConfigError):
    """Preflight validation failures with structured errors and warnings."""

    def __init__(
        self,
        message: str,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
    ) -> None:
        self.errors = errors if errors is not None else []
        self.warnings = warnings if warnings is not None else []
        super().__init__(message)


# ---------------------------------------------------------------------------
# Adapter errors
# ---------------------------------------------------------------------------


class AdapterError(GxAssessError):
    """Base for all adapter-related errors."""

    def __init__(
        self,
        message: str,
        adapter_name: str = "",
        engagement_id: str = "",
    ) -> None:
        self.adapter_name = adapter_name
        self.engagement_id = engagement_id
        super().__init__(message)


class PrerequisiteError(AdapterError):
    """Tool not installed or wrong version."""


class CollectionError(AdapterError):
    """Tool execution failed, timeout, or non-zero exit."""


class ParseError(AdapterError):
    """Raw output doesn't match expected format."""

    def __init__(
        self,
        message: str,
        adapter_name: str = "",
        engagement_id: str = "",
        check_id: str = "",
    ) -> None:
        self.check_id = check_id
        super().__init__(message, adapter_name, engagement_id)


class RawOutputValidationError(AdapterError):
    """Raw output payload fails structural validation at the tool boundary."""


# ---------------------------------------------------------------------------
# Module verification errors
# ---------------------------------------------------------------------------


class ModuleVerificationError(PrerequisiteError):
    """Module provenance verification failed."""

    def __init__(
        self,
        message: str,
        adapter_name: str = "",
        engagement_id: str = "",
        verification_result: Any = None,
    ) -> None:
        self.verification_result = verification_result
        super().__init__(message, adapter_name, engagement_id)


class ModuleProvenanceError(ModuleVerificationError):
    """Candidate found but rejected by provenance policy."""


class ModuleAmbiguityError(ModuleVerificationError):
    """Multiple candidates satisfy policy -- fail closed."""


class ModuleExecutionUnsupportedError(ModuleVerificationError):
    """Module cannot execute on this platform."""


class VerificationInfrastructureError(ModuleVerificationError):
    """Verification machinery itself failed."""

    def __init__(
        self,
        message: str,
        adapter_name: str = "",
        engagement_id: str = "",
        verification_result: Any = None,
        exit_code: int | None = None,
        stderr_snippet: str | None = None,
        report_path: str | None = None,
    ) -> None:
        self.exit_code = exit_code
        self.stderr_snippet = stderr_snippet
        self.report_path = report_path
        super().__init__(message, adapter_name, engagement_id, verification_result)


# ---------------------------------------------------------------------------
# Consolidation errors
# ---------------------------------------------------------------------------


class ConsolidationError(GxAssessError):
    """Base for consolidation-related errors."""


class DedupKeyConflictError(ConsolidationError):
    """Conflicting dedup key assignments across adapters."""


# ---------------------------------------------------------------------------
# QA errors
# ---------------------------------------------------------------------------


class QAError(GxAssessError):
    """Base for AI QA-related errors."""


class TokenBudgetExhaustedError(QAError):
    """AI QA token budget exhausted mid-pipeline."""


class QAQualityError(QAError):
    """Structurally valid but semantically nonsensical AI output."""


# ---------------------------------------------------------------------------
# Report errors
# ---------------------------------------------------------------------------


class ReportError(GxAssessError):
    """Base for report-related errors."""


class PayloadVersionError(ReportError):
    """Renderer doesn't support this payload schema version."""


class RendererDependencyError(ReportError):
    """Node.js or npm packages missing at render time."""


# ---------------------------------------------------------------------------
# Persistence errors
# ---------------------------------------------------------------------------


class PersistenceError(GxAssessError):
    """Base for persistence-related errors."""


class MigrationError(PersistenceError):
    """Schema migration failed."""


class ConfigSnapshotMirrorError(PersistenceError):
    """Raised when writing the filesystem mirror of config_snapshot fails.

    This is a disaster-recovery helper -- a failure here does not block
    normal pipeline execution, but it does mean `mseco replay` cannot
    recover this engagement after a DB wipe. The caller (pipeline
    runner) logs at ERROR level and continues.

    `engagement_id` is required -- every raise site in the mirror module
    has a bound engagement_id, and defaulting it would hide context from
    the operator log format string that relies on it.
    """

    def __init__(self, message: str, engagement_id: str) -> None:
        self.engagement_id = engagement_id
        super().__init__(message)


class LockTimeoutError(PersistenceError):
    """Advisory lock acquisition timed out."""

    def __init__(
        self,
        message: str,
        engagement_id: str = "",
        timeout_seconds: float = 0.0,
    ) -> None:
        self.engagement_id = engagement_id
        self.timeout_seconds = timeout_seconds
        super().__init__(message)


class InvalidTransitionError(PersistenceError):
    """Invalid engagement state transition attempted."""

    def __init__(
        self,
        message: str,
        from_state: str = "",
        to_state: str = "",
    ) -> None:
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(message)


# ---------------------------------------------------------------------------
# Pipeline errors
# ---------------------------------------------------------------------------


class PipelineError(GxAssessError):
    """Base for pipeline execution errors."""

    def __init__(
        self,
        message: str,
        engagement_id: str = "",
        stage: str = "",
    ) -> None:
        self.engagement_id = engagement_id
        self.stage = stage
        super().__init__(message)


class StaleStageError(PipelineError):
    """Stage found in RUNNING state from a previous (killed) process."""


class InvalidRawOutputError(PipelineError):
    """Persisted raw output fails re-validation during replay."""


class MissingRawOutputError(PipelineError):
    """Raw output files missing from filesystem during replay."""


class ManifestConfinementError(PipelineError):
    """Raised by confine_and_resolve() when a manifest fails security checks."""

    def __init__(
        self,
        message: str,
        engagement_id: str = "",
        stage: str = "",
        tool_slug: str = "",
        check_name: str = "",
        detail: str = "",
    ) -> None:
        self.tool_slug = tool_slug
        self.check_name = check_name
        self.detail = detail
        super().__init__(message, engagement_id, stage)
