"""Tests for Pydantic domain models."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone

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
    ReportKeyStats,
    ReportPayload,
    ResolvedManifest,
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
            native_check_id="MS.AAD.3.1v1",
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
                native_check_id="test:1",
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

    def test_rejects_bool_overall(self) -> None:
        with pytest.raises(ValidationError):
            ConfidenceScore(
                evidence_strength=0.9,
                corroborating_tools=1,
                data_freshness=0.95,
                provenance="system-generated",
                overall=True,  # type: ignore[arg-type]
            )

    def test_rejects_bool_corroborating_tools(self) -> None:
        with pytest.raises(ValidationError):
            ConfidenceScore(
                evidence_strength=0.9,
                corroborating_tools=True,  # type: ignore[arg-type]
                data_freshness=0.95,
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
    def _make_valid_raw(self) -> RawToolOutput:
        from gxassessms.core.domain.models import ArtifactRecord

        return RawToolOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.7.1",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
            file_manifest={
                "scubagear/ScubaResults.json": ArtifactRecord(
                    encoding="utf-8",
                    sha256="f" * 64,
                ),
            },
            execution_metadata={},
        )

    def test_create_valid(self) -> None:
        raw = self._make_valid_raw()
        assert raw.tool_slug == "scubagear"
        assert raw.manifest_version == "1.0.0"

    def test_rejects_extra_fields(self) -> None:
        from gxassessms.core.domain.models import ArtifactRecord

        with pytest.raises(ValidationError):
            RawToolOutput(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                schema_version="1.7.1",
                manifest_version="1.0.0",
                timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
                file_manifest={
                    "scubagear/r.json": ArtifactRecord(encoding="utf-8", sha256="a" * 64),
                },
                execution_metadata={},
                bonus="bad",
            )

    def test_timestamp_must_be_utc(self) -> None:
        from gxassessms.core.domain.models import ArtifactRecord

        with pytest.raises(ValidationError):
            RawToolOutput(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                schema_version="1.7.1",
                manifest_version="1.0.0",
                timestamp=datetime(2026, 4, 1, 10, 0, 0),  # naive
                file_manifest={
                    "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256="a" * 64),
                },
                execution_metadata={},
            )

    def test_rejects_backslash_in_manifest_key(self) -> None:
        from gxassessms.core.domain.models import ArtifactRecord

        with pytest.raises(ValidationError, match="backslash"):
            RawToolOutput(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                schema_version="1.7.1",
                manifest_version="1.0.0",
                timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
                file_manifest={
                    "scubagear\\results.json": ArtifactRecord(encoding="utf-8", sha256="a" * 64),
                },
                execution_metadata={},
            )

    def test_rejects_absolute_path_in_manifest_key(self) -> None:
        from gxassessms.core.domain.models import ArtifactRecord

        with pytest.raises(ValidationError, match="absolute"):
            RawToolOutput(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                schema_version="1.7.1",
                manifest_version="1.0.0",
                timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
                file_manifest={
                    "/etc/passwd": ArtifactRecord(encoding="utf-8", sha256="a" * 64),
                },
                execution_metadata={},
            )

    def test_rejects_dotdot_traversal_in_manifest_key(self) -> None:
        from gxassessms.core.domain.models import ArtifactRecord

        with pytest.raises(ValidationError, match="traversal"):
            RawToolOutput(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                schema_version="1.7.1",
                manifest_version="1.0.0",
                timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
                file_manifest={
                    "scubagear/../etc/passwd": ArtifactRecord(encoding="utf-8", sha256="a" * 64),
                },
                execution_metadata={},
            )

    def test_rejects_empty_manifest(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            RawToolOutput(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                schema_version="1.7.1",
                manifest_version="1.0.0",
                timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
                file_manifest={},
                execution_metadata={},
            )

    def test_rejects_invalid_tool_slug_format(self) -> None:
        from gxassessms.core.domain.models import ArtifactRecord

        with pytest.raises(ValidationError, match="slug"):
            RawToolOutput(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="ScubaGear",  # uppercase not allowed
                schema_version="1.7.1",
                manifest_version="1.0.0",
                timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
                file_manifest={
                    "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256="a" * 64),
                },
                execution_metadata={},
            )

    def test_rejects_slug_starting_with_hyphen(self) -> None:
        from gxassessms.core.domain.models import ArtifactRecord

        with pytest.raises(ValidationError, match="slug"):
            RawToolOutput(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="-scubagear",
                schema_version="1.7.1",
                manifest_version="1.0.0",
                timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
                file_manifest={
                    "scubagear/results.json": ArtifactRecord(encoding="utf-8", sha256="a" * 64),
                },
                execution_metadata={},
            )


class TestAdapterResult:
    def _make_resolved_manifest(self) -> ResolvedManifest:
        from gxassessms.core.domain.models import ArtifactRecord

        return ResolvedManifest(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={
                "/engagements/artifacts/scubagear/TestResults.json": ArtifactRecord(
                    encoding="utf-8",
                    sha256="a" * 64,
                ),
            },
            execution_metadata={},
        )

    def test_success_result_has_raw_output(self) -> None:
        rm = self._make_resolved_manifest()
        ar = AdapterResult(
            adapter_name="scubagear",
            status=AdapterRunStatus.SUCCESS,
            raw_output=rm,
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

    def test_rejects_negative_duration(self) -> None:
        with pytest.raises(ValidationError):
            AdapterResult(
                adapter_name="scubagear",
                status=AdapterRunStatus.FAILED,
                error="failed",
                duration_seconds=-5.0,
            )

    def test_success_without_raw_output_raises(self) -> None:
        with pytest.raises(ValidationError, match="requires raw_output"):
            AdapterResult(
                adapter_name="scubagear",
                status=AdapterRunStatus.SUCCESS,
                raw_output=None,
                duration_seconds=120.5,
            )

    def test_failed_without_error_raises(self) -> None:
        with pytest.raises(ValidationError, match="requires error"):
            AdapterResult(
                adapter_name="scubagear",
                status=AdapterRunStatus.FAILED,
                raw_output=None,
                duration_seconds=5.0,
            )

    def test_timeout_without_error_raises(self) -> None:
        with pytest.raises(ValidationError, match="requires error"):
            AdapterResult(
                adapter_name="scubagear",
                status=AdapterRunStatus.TIMEOUT,
                raw_output=None,
                duration_seconds=600.0,
            )

    def test_success_with_error_raises(self) -> None:
        rm = self._make_resolved_manifest()
        with pytest.raises(ValidationError, match="must not carry an error"):
            AdapterResult(
                adapter_name="scubagear",
                status=AdapterRunStatus.SUCCESS,
                raw_output=rm,
                error="unexpected",
                duration_seconds=120.5,
            )

    def test_failed_preserves_raw_output_for_replay(self) -> None:
        rm = self._make_resolved_manifest()
        ar = AdapterResult(
            adapter_name="scubagear",
            status=AdapterRunStatus.FAILED,
            raw_output=rm,
            error="ParseError: invalid JSON in TestResults.json",
            duration_seconds=5.0,
        )
        assert ar.raw_output is not None
        assert ar.error is not None

    def test_skipped_with_raw_output_raises(self) -> None:
        rm = self._make_resolved_manifest()
        with pytest.raises(ValidationError, match="must not carry raw_output"):
            AdapterResult(
                adapter_name="scubagear",
                status=AdapterRunStatus.SKIPPED,
                raw_output=rm,
                duration_seconds=0.0,
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

    def test_narratives_accept_none_values(self) -> None:
        """Narratives with None values (e.g., omitted findings_narrative) must be accepted."""
        rp = ReportPayload(
            engagement_id="eng-001",
            tenant_name="Acme Healthcare",
            assessment_date="2026-03-25",
            tool_sources=["ScubaGear"],
            findings=[],
            coverage=[],
            narratives={"executive_summary": "Good", "findings_narrative": None},
            metadata={},
        )
        assert rp.narratives["findings_narrative"] is None

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            ReportPayload(
                schema_verison="2.0.0",  # type: ignore[call-arg]
                engagement_id="eng-001",
                tenant_name="Acme Healthcare",
                assessment_date="2026-03-25",
                tool_sources=["ScubaGear"],
                findings=[],
                coverage=[],
                narratives={},
                metadata={},
            )


class TestReportKeyStats:
    def test_rejects_negative_total_findings(self) -> None:
        with pytest.raises(ValidationError):
            ReportKeyStats(
                total_findings=-1,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                tools_run=1,
                tools_failed=0,
                controls_assessed=10,
                controls_not_assessed=0,
            )

    def test_rejects_negative_tools_failed(self) -> None:
        with pytest.raises(ValidationError):
            ReportKeyStats(
                total_findings=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                tools_run=1,
                tools_failed=-3,
                controls_assessed=10,
                controls_not_assessed=0,
            )

    def test_rejects_bool_counter(self) -> None:
        with pytest.raises(ValidationError):
            ReportKeyStats(
                total_findings=True,  # type: ignore[arg-type]
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                tools_run=1,
                tools_failed=0,
                controls_assessed=10,
                controls_not_assessed=0,
            )


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

    def test_normalizes_non_utc_timestamps_to_utc(self) -> None:
        ist = timezone(timedelta(hours=5, minutes=30))
        trr = ToolRunResult(
            tool=ToolSource.SCUBAGEAR,
            started_at=datetime(2026, 3, 25, 15, 30, 0, tzinfo=ist),
            completed_at=datetime(2026, 3, 25, 15, 45, 0, tzinfo=ist),
            status=AdapterRunStatus.SUCCESS,
            finding_count=0,
        )
        assert trr.started_at.tzinfo == UTC
        assert trr.started_at == datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC)
        assert trr.completed_at == datetime(2026, 3, 25, 10, 15, 0, tzinfo=UTC)

    def test_rejects_completed_before_started(self) -> None:
        with pytest.raises(ValidationError, match=r"completed_at must be >= started_at"):
            ToolRunResult(
                tool=ToolSource.SCUBAGEAR,
                started_at=datetime(2026, 3, 25, 10, 15, 0, tzinfo=UTC),
                completed_at=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
                status=AdapterRunStatus.SUCCESS,
                finding_count=0,
            )

    def test_rejects_negative_finding_count(self) -> None:
        with pytest.raises(ValidationError):
            ToolRunResult(
                tool=ToolSource.SCUBAGEAR,
                started_at=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
                completed_at=datetime(2026, 3, 25, 10, 15, 0, tzinfo=UTC),
                status=AdapterRunStatus.SUCCESS,
                finding_count=-1,
            )

    def test_failed_without_error_raises(self) -> None:
        with pytest.raises(ValidationError, match="requires error"):
            ToolRunResult(
                tool=ToolSource.SCUBAGEAR,
                started_at=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
                completed_at=datetime(2026, 3, 25, 10, 15, 0, tzinfo=UTC),
                status=AdapterRunStatus.FAILED,
                finding_count=0,
            )

    def test_timeout_without_error_raises(self) -> None:
        with pytest.raises(ValidationError, match="requires error"):
            ToolRunResult(
                tool=ToolSource.SCUBAGEAR,
                started_at=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
                completed_at=datetime(2026, 3, 25, 10, 15, 0, tzinfo=UTC),
                status=AdapterRunStatus.TIMEOUT,
                finding_count=0,
            )

    def test_rejects_bool_finding_count(self) -> None:
        with pytest.raises(ValidationError):
            ToolRunResult(
                tool=ToolSource.SCUBAGEAR,
                started_at=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
                completed_at=datetime(2026, 3, 25, 10, 15, 0, tzinfo=UTC),
                status=AdapterRunStatus.SUCCESS,
                finding_count=True,  # type: ignore[arg-type]
            )

    def test_success_with_error_raises(self) -> None:
        with pytest.raises(ValidationError, match="must not carry an error"):
            ToolRunResult(
                tool=ToolSource.SCUBAGEAR,
                started_at=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
                completed_at=datetime(2026, 3, 25, 10, 15, 0, tzinfo=UTC),
                status=AdapterRunStatus.SUCCESS,
                finding_count=0,
                error="unexpected",
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

    def test_accepts_valid_credential_refs(self) -> None:
        credential_refs = {
            "client_secret": "GX_CLIENT_SECRET",  # pragma: allowlist secret
            "graph_secret": "env:GX_GRAPH_SECRET",  # pragma: allowlist secret
            "legacy_secret": "_CLIENT_SECRET",  # pragma: allowlist secret
            "legacy_graph_secret": "env:_GRAPH_SECRET",  # pragma: allowlist secret
            "vault_secret": "key_vault:tenant/prod/client-secret",  # pragma: allowlist secret
            "shared_secret": "encrypted_file:shared/graph-app",  # pragma: allowlist secret
        }

        ctx = AuthContext(credential_refs=credential_refs)

        assert ctx.credential_refs == credential_refs

    def test_rejects_invalid_credential_refs(self) -> None:
        invalid_refs = (
            "supersecret",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "",
            " env:GX_CLIENT_SECRET",
            "env:GX CLIENT SECRET",
            "gx_client_secret",
            "key_vault:tenant:prod/client-secret",
        )

        for invalid_ref in invalid_refs:
            with pytest.raises(ValidationError, match="credential_refs"):
                AuthContext(credential_refs={"client_secret": invalid_ref})

    def test_rejects_mixed_valid_and_invalid_refs_without_partial_success(self) -> None:
        with pytest.raises(ValidationError, match="credential_refs\\['api_key'\\]"):
            AuthContext(
                credential_refs={
                    "client_secret": "GX_CLIENT_SECRET",  # pragma: allowlist secret
                    "api_key": "supersecret",  # pragma: allowlist secret
                }
            )

    def test_model_validate_rejects_invalid_credential_refs(self) -> None:
        with pytest.raises(ValidationError, match="credential_refs\\['client_secret'\\]"):
            AuthContext.model_validate(
                {
                    "credential_refs": {
                        "client_secret": "supersecret",  # pragma: allowlist secret
                    }
                }
            )

    def test_valid_refs_serialize_as_refs_while_token_remains_masked(self) -> None:
        ctx = AuthContext(
            token="my-secret-token",
            credential_refs={
                "client_secret": "GX_CLIENT_SECRET",  # pragma: allowlist secret
                "vault_secret": "key_vault:tenant/prod/client-secret",  # pragma: allowlist secret
            },
        )

        payload = json.loads(ctx.model_dump_json())

        assert payload["credential_refs"] == {
            "client_secret": "GX_CLIENT_SECRET",  # pragma: allowlist secret
            "vault_secret": "key_vault:tenant/prod/client-secret",  # pragma: allowlist secret
        }
        assert payload["token"] == "**********"
        assert "my-secret-token" not in ctx.model_dump_json()

    def test_validation_error_message_includes_ref_key_but_not_secret_value(self) -> None:
        with pytest.raises(ValidationError) as excinfo:
            AuthContext(
                credential_refs={"client_secret": "supersecret"}  # pragma: allowlist secret
            )

        error_message = str(excinfo.value)

        assert "client_secret" in error_message
        assert "supersecret" not in error_message

    def test_rejects_naive_expires_at(self) -> None:
        with pytest.raises(ValidationError, match="timezone-aware"):
            AuthContext(expires_at=datetime(2026, 3, 25, 12, 0, 0))

    def test_normalizes_expires_at_to_utc(self) -> None:
        ist = timezone(timedelta(hours=5, minutes=30))
        ctx = AuthContext(expires_at=datetime(2026, 3, 25, 17, 30, 0, tzinfo=ist))
        assert ctx.expires_at is not None
        assert ctx.expires_at.tzinfo == UTC
        assert ctx.expires_at == datetime(2026, 3, 25, 12, 0, 0, tzinfo=UTC)


class TestArtifactRecord:
    def test_create_valid(self) -> None:
        from gxassessms.core.domain.models import ArtifactRecord

        rec = ArtifactRecord(
            encoding="utf-8",
            sha256="a" * 64,
        )
        assert rec.encoding == "utf-8"
        assert rec.sha256 == "a" * 64

    def test_rejects_short_sha256(self) -> None:
        from gxassessms.core.domain.models import ArtifactRecord

        with pytest.raises(ValidationError):
            ArtifactRecord(encoding="utf-8", sha256="abc123")

    def test_rejects_uppercase_sha256(self) -> None:
        from gxassessms.core.domain.models import ArtifactRecord

        with pytest.raises(ValidationError):
            ArtifactRecord(encoding="utf-8", sha256="A" * 64)

    def test_rejects_extra_fields(self) -> None:
        from gxassessms.core.domain.models import ArtifactRecord

        with pytest.raises(ValidationError):
            ArtifactRecord(encoding="utf-8", sha256="a" * 64, extra="bad")

    def test_binary_encoding(self) -> None:
        from gxassessms.core.domain.models import ArtifactRecord

        rec = ArtifactRecord(encoding="binary", sha256="b" * 64)
        assert rec.encoding == "binary"


class TestCollectedArtifact:
    def test_create_valid(self) -> None:
        from gxassessms.core.domain.models import CollectedArtifact

        ca = CollectedArtifact(
            source_path="C:\\Users\\output\\ScubaResults.json",
            target_relpath="scubagear/ScubaResults.json",
            encoding="utf-8",
            sha256="c" * 64,
        )
        assert ca.source_path == "C:\\Users\\output\\ScubaResults.json"
        assert ca.target_relpath == "scubagear/ScubaResults.json"

    def test_rejects_bad_sha256(self) -> None:
        from gxassessms.core.domain.models import CollectedArtifact

        with pytest.raises(ValidationError):
            CollectedArtifact(
                source_path="/home/user/results.json",
                target_relpath="scubagear/results.json",
                encoding="utf-8",
                sha256="too-short",
            )


class TestCollectionOutput:
    def test_create_valid(self) -> None:
        from gxassessms.core.domain.models import CollectedArtifact, CollectionOutput

        co = CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.7.1",
            timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
            artifacts=[
                CollectedArtifact(
                    source_path="C:\\output\\ScubaResults.json",
                    target_relpath="scubagear/ScubaResults.json",
                    encoding="utf-8",
                    sha256="d" * 64,
                )
            ],
            execution_metadata={"modules": ["AAD"]},
        )
        assert co.tool_slug == "scubagear"
        assert len(co.artifacts) == 1

    def test_timestamp_must_be_utc(self) -> None:
        from gxassessms.core.domain.models import CollectionOutput

        with pytest.raises(ValidationError):
            CollectionOutput(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                schema_version="1.7.1",
                timestamp=datetime(2026, 4, 1, 10, 0, 0),  # naive
                artifacts=[],
                execution_metadata={},
            )


class TestCollectionResult:
    def test_success_requires_collection_output(self) -> None:
        from gxassessms.core.domain.models import CollectionOutput, CollectionResult

        co = CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.7.1",
            timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
            artifacts=[],
            execution_metadata={},
        )
        cr = CollectionResult(
            adapter_name="scubagear",
            status=AdapterRunStatus.SUCCESS,
            collection_output=co,
            duration_seconds=5.0,
        )
        assert cr.collection_output is not None

    def test_success_without_output_raises(self) -> None:
        from gxassessms.core.domain.models import CollectionResult

        with pytest.raises(ValidationError):
            CollectionResult(
                adapter_name="scubagear",
                status=AdapterRunStatus.SUCCESS,
                collection_output=None,
                duration_seconds=5.0,
            )

    def test_success_with_error_raises(self) -> None:
        from gxassessms.core.domain.models import CollectionOutput, CollectionResult

        co = CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.7.1",
            timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
            artifacts=[],
            execution_metadata={},
        )
        with pytest.raises(ValidationError):
            CollectionResult(
                adapter_name="scubagear",
                status=AdapterRunStatus.SUCCESS,
                collection_output=co,
                error="oops",
                duration_seconds=5.0,
            )

    def test_failed_requires_error(self) -> None:
        from gxassessms.core.domain.models import CollectionResult

        with pytest.raises(ValidationError):
            CollectionResult(
                adapter_name="scubagear",
                status=AdapterRunStatus.FAILED,
                duration_seconds=5.0,
            )

    def test_failed_with_error(self) -> None:
        from gxassessms.core.domain.models import CollectionResult

        cr = CollectionResult(
            adapter_name="scubagear",
            status=AdapterRunStatus.FAILED,
            error="PowerShell timed out",
            duration_seconds=5.0,
        )
        assert cr.error == "PowerShell timed out"
        assert cr.collection_output is None

    def test_skipped_must_not_carry_output(self) -> None:
        from gxassessms.core.domain.models import CollectionOutput, CollectionResult

        co = CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.7.1",
            timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
            artifacts=[],
            execution_metadata={},
        )
        with pytest.raises(ValidationError):
            CollectionResult(
                adapter_name="scubagear",
                status=AdapterRunStatus.SKIPPED,
                collection_output=co,
                duration_seconds=0.0,
            )


class TestResolvedManifest:
    def test_create_valid(self) -> None:
        from gxassessms.core.domain.models import ArtifactRecord, ResolvedManifest

        rm = ResolvedManifest(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.7.1",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
            file_manifest={
                "/engagement/raw-output/artifacts/scubagear/ScubaResults.json": ArtifactRecord(
                    encoding="utf-8", sha256="e" * 64
                ),
            },
            execution_metadata={},
        )
        assert rm.tool_slug == "scubagear"
        assert len(rm.file_manifest) == 1

    def test_rejects_extra_fields(self) -> None:
        from gxassessms.core.domain.models import ResolvedManifest

        with pytest.raises(ValidationError):
            ResolvedManifest(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                schema_version="1.7.1",
                manifest_version="1.0.0",
                timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
                file_manifest={},
                execution_metadata={},
                bonus="bad",
            )
