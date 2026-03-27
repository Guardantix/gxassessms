"""Tests for the typed exception hierarchy."""

import pytest

from gxassessms.core.contracts.errors import (
    AdapterError,
    CollectionError,
    ConfigError,
    ConfigValidationError,
    ConsolidationError,
    DedupKeyConflictError,
    GxAssessError,
    LockTimeoutError,
    MigrationError,
    ParseError,
    PayloadVersionError,
    PersistenceError,
    PrerequisiteError,
    QAError,
    QAQualityError,
    RawOutputValidationError,
    RendererDependencyError,
    ReportError,
    TokenBudgetExhaustedError,
)


class TestExceptionHierarchy:
    def test_all_exceptions_inherit_from_gxassess_error(self) -> None:
        exceptions = [
            ConfigError,
            ConfigValidationError,
            AdapterError,
            PrerequisiteError,
            CollectionError,
            ParseError,
            RawOutputValidationError,
            ConsolidationError,
            DedupKeyConflictError,
            QAError,
            TokenBudgetExhaustedError,
            QAQualityError,
            ReportError,
            PayloadVersionError,
            RendererDependencyError,
            PersistenceError,
            MigrationError,
            LockTimeoutError,
        ]
        for exc_class in exceptions:
            assert issubclass(exc_class, GxAssessError)

    def test_adapter_error_subtypes(self) -> None:
        assert issubclass(PrerequisiteError, AdapterError)
        assert issubclass(CollectionError, AdapterError)
        assert issubclass(ParseError, AdapterError)
        assert issubclass(RawOutputValidationError, AdapterError)

    def test_config_error_subtypes(self) -> None:
        assert issubclass(ConfigValidationError, ConfigError)

    def test_qa_error_subtypes(self) -> None:
        assert issubclass(TokenBudgetExhaustedError, QAError)
        assert issubclass(QAQualityError, QAError)

    def test_report_error_subtypes(self) -> None:
        assert issubclass(PayloadVersionError, ReportError)
        assert issubclass(RendererDependencyError, ReportError)

    def test_persistence_error_subtypes(self) -> None:
        assert issubclass(MigrationError, PersistenceError)
        assert issubclass(LockTimeoutError, PersistenceError)


class TestExceptionContext:
    def test_adapter_error_carries_context(self) -> None:
        err = CollectionError(
            message="ScubaGear timed out",
            adapter_name="scubagear",
            engagement_id="eng-001",
        )
        assert err.adapter_name == "scubagear"
        assert err.engagement_id == "eng-001"
        assert "ScubaGear timed out" in str(err)

    def test_parse_error_carries_check_id(self) -> None:
        err = ParseError(
            message="Unexpected format",
            adapter_name="scubagear",
            engagement_id="eng-001",
            check_id="MS.AAD.3.1v1",
        )
        assert err.check_id == "MS.AAD.3.1v1"

    def test_config_validation_error_carries_details(self) -> None:
        err = ConfigValidationError(
            message="Invalid config",
            errors=["missing tenant_id"],
            warnings=["no tools enabled"],
        )
        assert err.errors == ["missing tenant_id"]
        assert err.warnings == ["no tools enabled"]

    def test_lock_timeout_error_carries_engagement_id(self) -> None:
        err = LockTimeoutError(
            message="Lock held by another process",
            engagement_id="eng-001",
            timeout_seconds=30.0,
        )
        assert err.engagement_id == "eng-001"
        assert err.timeout_seconds == 30.0

    def test_config_validation_error_with_explicit_empty_lists(self) -> None:
        """Passing errors=[] and warnings=[] must preserve empty lists, not replace them."""
        err = ConfigValidationError(
            message="Structurally invalid",
            errors=[],
            warnings=[],
        )
        assert err.errors == []
        assert err.warnings == []
        assert isinstance(err.errors, list)
        assert isinstance(err.warnings, list)

    def test_config_validation_error_with_none_defaults_to_empty_list(self) -> None:
        """Omitting errors/warnings must default to empty lists."""
        err = ConfigValidationError(message="Bare error")
        assert err.errors == []
        assert err.warnings == []

    def test_gxassess_error_is_catchable_as_exception(self) -> None:
        with pytest.raises(Exception, match="test"):
            raise GxAssessError("test")
