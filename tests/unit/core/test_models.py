"""Tests for Pydantic domain models."""

from datetime import UTC, datetime

import pytest
from pydantic import SecretStr, ValidationError

from gxassessms.core.domain.enums import (
    AdapterRunStatus,
    Category,
    CoverageStatus,
    FindingStatus,
    Severity,
    ToolSource,
)
from gxassessms.core.domain.models import (
    AdapterResult,
    AuthContext,
    ConfidenceScore,
    ConsolidatedFinding,
    CoverageRecord,
    Finding,
    RawToolOutput,
    RemediationPhase,
    ReportPayload,
    SourceEvidence,
    ToolObservation,
    ToolRunResult,
)


class TestSourceEvidence:
    def test_create_minimal(self) -> None:
        ev = SourceEvidence(
            tool=ToolSource.SCUBAGEAR,
            check_id="MS.AAD.3.1v1",
            raw_data={"result": "Fail"},
        )
        assert ev.tool == ToolSource.SCUBAGEAR
        assert ev.check_id == "MS.AAD.3.1v1"


class TestToolObservation:
    def test_create_with_required_fields(self) -> None:
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.3.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.3.1v1",
            title="MFA for privileged roles",
            native_severity="Shall",
            native_status="Fail",
            description="Multi-factor authentication is not enabled.",
        )
        assert obs.observation_id == "scubagear:MS.AAD.3.1v1"
        assert obs.benchmark_refs == []


class TestFinding:
    def test_create_normalized_finding(self) -> None:
        f = Finding(
            observation_id="scubagear:MS.AAD.3.1v1",
            finding_key="cis:m365:1.1.1",
            tool=ToolSource.SCUBAGEAR,
            title="MFA for privileged roles",
            severity=Severity.CRITICAL,
            status=FindingStatus.FAIL,
            category=Category.IDENTITY_ACCESS,
            description="MFA is not enabled for privileged roles.",
            dedup_keys=["cis:m365:1.1.1"],
        )
        assert f.severity == Severity.CRITICAL
        assert f.category == Category.IDENTITY_ACCESS

    def test_dedup_keys_required_nonempty(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                observation_id="test:1",
                finding_key="test:1",
                tool=ToolSource.SCUBAGEAR,
                title="Test",
                severity=Severity.LOW,
                status=FindingStatus.FAIL,
                category=Category.IDENTITY_ACCESS,
                description="Test",
                dedup_keys=[],
            )


class TestConfidenceScore:
    def test_create_with_all_fields(self) -> None:
        cs = ConfidenceScore(
            evidence_strength=0.9,
            corroborating_tools=3,
            data_freshness=0.95,
            provenance="system-generated",
            overall=0.88,
        )
        assert cs.overall == 0.88
        assert cs.corroborating_tools == 3

    def test_overall_bounded_0_to_1(self) -> None:
        with pytest.raises(ValidationError):
            ConfidenceScore(
                evidence_strength=0.9,
                corroborating_tools=1,
                data_freshness=0.95,
                provenance="system-generated",
                overall=1.5,
            )

    def test_rejects_invalid_provenance(self) -> None:
        with pytest.raises(ValidationError):
            ConfidenceScore(
                evidence_strength=0.9,
                corroborating_tools=1,
                data_freshness=0.95,
                provenance="invalid-provenance",
                overall=0.88,
            )

    def test_rejects_negative_evidence_strength(self) -> None:
        with pytest.raises(ValidationError):
            ConfidenceScore(
                evidence_strength=-0.1,
                corroborating_tools=1,
                data_freshness=0.95,
                provenance="system-generated",
                overall=0.88,
            )

    def test_rejects_negative_corroborating_tools(self) -> None:
        with pytest.raises(ValidationError):
            ConfidenceScore(
                evidence_strength=0.9,
                corroborating_tools=-1,
                data_freshness=0.95,
                provenance="system-generated",
                overall=0.88,
            )

    def test_rejects_data_freshness_above_one(self) -> None:
        with pytest.raises(ValidationError):
            ConfidenceScore(
                evidence_strength=0.9,
                corroborating_tools=1,
                data_freshness=1.1,
                provenance="system-generated",
                overall=0.88,
            )


class TestConsolidatedFinding:
    def _make_source(self) -> SourceEvidence:
        return SourceEvidence(
            tool=ToolSource.SCUBAGEAR,
            check_id="MS.AAD.3.1v1",
            raw_data={},
        )

    def _make_confidence(self) -> ConfidenceScore:
        return ConfidenceScore(
            evidence_strength=0.9,
            corroborating_tools=2,
            data_freshness=0.95,
            provenance="system-generated",
            overall=0.88,
        )

    def test_create_with_confidence(self) -> None:
        cf = ConsolidatedFinding(
            finding_instance_id="uuid-001",
            finding_key="cis:m365:1.1.1",
            title="MFA for privileged roles",
            severity=Severity.CRITICAL,
            status=FindingStatus.FAIL,
            category=Category.IDENTITY_ACCESS,
            description="MFA is not enabled.",
            sources=[self._make_source()],
            confidence=self._make_confidence(),
            benchmark_refs=["CIS M365 1.1.1"],
        )
        assert cf.confidence.overall == 0.88
        assert cf.benchmark_refs == ["CIS M365 1.1.1"]

    def test_empty_sources_raises(self) -> None:
        with pytest.raises(ValidationError, match="sources"):
            ConsolidatedFinding(
                finding_instance_id="uuid-001",
                finding_key="cis:m365:1.1.1",
                title="MFA",
                severity=Severity.CRITICAL,
                status=FindingStatus.FAIL,
                category=Category.IDENTITY_ACCESS,
                description="Test",
                sources=[],
                confidence=self._make_confidence(),
            )


class TestCoverageRecord:
    def test_create_coverage_record(self) -> None:
        cr = CoverageRecord(
            control_id="CIS M365 1.1.1",
            tool=ToolSource.SCUBAGEAR,
            status=CoverageStatus.ASSESSED,
            reason=None,
        )
        assert cr.status == CoverageStatus.ASSESSED

    def test_rejects_invalid_status(self) -> None:
        with pytest.raises(ValidationError):
            CoverageRecord(
                control_id="CIS M365 1.1.1",
                tool=ToolSource.SCUBAGEAR,
                status="invalid_status",  # type: ignore[arg-type]
            )


class TestRawToolOutput:
    def test_create_with_schema_version(self) -> None:
        rto = RawToolOutput(
            tool=ToolSource.SCUBAGEAR,
            schema_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={"TestResults.json": "utf-8"},
            execution_metadata={"exit_code": 0},
        )
        assert rto.schema_version == "1.0.0"
        assert rto.file_manifest["TestResults.json"] == "utf-8"

    def test_rejects_naive_timestamp(self) -> None:
        with pytest.raises(ValidationError, match="timezone-aware"):
            RawToolOutput(
                tool=ToolSource.SCUBAGEAR,
                schema_version="1.0.0",
                timestamp=datetime(2026, 3, 25, 10, 0, 0),
                file_manifest={},
                execution_metadata={},
            )


class TestAdapterResult:
    def test_success_result_has_raw_output(self) -> None:
        rto = RawToolOutput(
            tool=ToolSource.SCUBAGEAR,
            schema_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={},
            execution_metadata={},
        )
        ar = AdapterResult(
            adapter_name="scubagear",
            status=AdapterRunStatus.SUCCESS,
            raw_output=rto,
            error=None,
            duration_seconds=120.5,
        )
        assert ar.raw_output is not None

    def test_failed_result_has_no_raw_output(self) -> None:
        ar = AdapterResult(
            adapter_name="scubagear",
            status=AdapterRunStatus.FAILED,
            raw_output=None,
            error="Connection refused",
            duration_seconds=5.0,
        )
        assert ar.raw_output is None
        assert ar.error == "Connection refused"

    def test_rejects_invalid_status(self) -> None:
        with pytest.raises(ValidationError):
            AdapterResult(
                adapter_name="scubagear",
                status="INVALID",  # type: ignore[arg-type]
                duration_seconds=5.0,
            )


class TestReportPayload:
    def test_default_schema_version(self) -> None:
        rp = ReportPayload(
            engagement_id="eng-001",
            tenant_name="Acme Healthcare",
            assessment_date="2026-03-25",
            tool_sources=["ScubaGear"],
            findings=[],
            coverage=[],
            narratives={},
            metadata={},
        )
        assert rp.schema_version == "1.0.0"


class TestToolRunResult:
    def test_create_tool_run_result(self) -> None:
        trr = ToolRunResult(
            tool=ToolSource.SCUBAGEAR,
            started_at=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            completed_at=datetime(2026, 3, 25, 10, 15, 0, tzinfo=UTC),
            status=AdapterRunStatus.SUCCESS,
            finding_count=42,
            error=None,
        )
        assert trr.finding_count == 42

    def test_rejects_naive_started_at(self) -> None:
        with pytest.raises(ValidationError, match="timezone-aware"):
            ToolRunResult(
                tool=ToolSource.SCUBAGEAR,
                started_at=datetime(2026, 3, 25, 10, 0, 0),
                completed_at=datetime(2026, 3, 25, 10, 15, 0, tzinfo=UTC),
                status=AdapterRunStatus.SUCCESS,
                finding_count=0,
            )

    def test_rejects_naive_completed_at(self) -> None:
        with pytest.raises(ValidationError, match="timezone-aware"):
            ToolRunResult(
                tool=ToolSource.SCUBAGEAR,
                started_at=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
                completed_at=datetime(2026, 3, 25, 10, 15, 0),
                status=AdapterRunStatus.SUCCESS,
                finding_count=0,
            )


class TestRemediationPhase:
    def test_rejects_invalid_phase(self) -> None:
        with pytest.raises(ValidationError):
            RemediationPhase(
                phase="INVALID_PHASE",  # type: ignore[arg-type]
                title="Test",
                description="Test",
            )


class TestAuthContext:
    def test_token_is_secret_str(self) -> None:
        ctx = AuthContext(
            token="my-secret-token",
            credential_refs={},
        )
        assert isinstance(ctx.token, SecretStr)
        assert ctx.token.get_secret_value() == "my-secret-token"
        assert "my-secret-token" not in repr(ctx)
