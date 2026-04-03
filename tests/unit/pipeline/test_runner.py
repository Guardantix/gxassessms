"""Tests for pipeline._runner stage-loop branches and helper functions."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest

from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.contracts.errors import PipelineError
from gxassessms.core.contracts.types import AdapterRunStatus
from gxassessms.core.domain.enums import (
    Category,
    CoverageStatus,
    FindingStatus,
    Severity,
    ToolSource,
)
from gxassessms.core.domain.models import (
    AdapterResult,
    ConfidenceScore,
    ConsolidatedFinding,
    CoverageRecord,
    Finding,
    RawToolOutput,
    SourceEvidence,
    ToolObservation,
)
from gxassessms.pipeline._runner import (
    _build_report_payload,
    _get_stage_output,
    _merge_adapter_map,
    _recover_stale_state,
    _rehydrate_upstream_state,
    _require_in_memory,
    run_stages,
)
from gxassessms.pipeline.orchestrator import Orchestrator
from gxassessms.pipeline.stages import Stage
from gxassessms.pipeline.state import EngagementState


def _make_config(**overrides: object) -> EngagementConfig:
    defaults: dict[str, object] = {
        "client_name": "Test Client",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "auth": AuthConfig(
            method="client_credential",
            tenant_id="00000000-0000-0000-0000-000000000001",
            client_id="00000000-0000-0000-0000-000000000002",
            client_secret_env="GX_SECRET",  # pragma: allowlist secret
        ),
        "tools": {
            "scubagear": ToolConfig(enabled=True),
            "maester": ToolConfig(enabled=True),
            "monkey365": ToolConfig(enabled=False),
        },
    }
    defaults.update(overrides)
    return EngagementConfig(**defaults)


def _make_raw_output(tool: ToolSource = ToolSource.SCUBAGEAR) -> RawToolOutput:
    return RawToolOutput(
        tool=tool,
        schema_version="1.0.0",
        timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
        file_manifest={"results.json": "utf-8"},
        execution_metadata={"exit_code": 0},
    )


def _make_adapter_result(
    *,
    adapter_name: str = "scubagear",
    tool: ToolSource = ToolSource.SCUBAGEAR,
) -> AdapterResult:
    return AdapterResult(
        adapter_name=adapter_name,
        status=AdapterRunStatus.SUCCESS,
        raw_output=_make_raw_output(tool),
        error=None,
        duration_seconds=1.25,
    )


def _make_observation(
    *,
    tool: ToolSource = ToolSource.SCUBAGEAR,
    check_id: str = "MS.AAD.3.1v1",
) -> ToolObservation:
    return ToolObservation(
        observation_id=f"{tool.value.lower()}:{check_id}",
        tool=tool,
        native_check_id=check_id,
        title=f"Check {check_id}",
        native_severity="Shall",
        native_status="Fail",
        description="Observation under test",
        raw_data={"result": "fail"},
        benchmark_refs=["CIS M365 1.1.1"],
    )


def _make_finding(
    *,
    key: str = "cis:m365:1.1.1",
    tool: ToolSource = ToolSource.SCUBAGEAR,
) -> Finding:
    return Finding(
        observation_id=f"{tool.value.lower()}:{key}",
        native_check_id="MS.AAD.3.1v1",
        finding_key=key,
        tool=tool,
        title=f"Finding {key}",
        severity=Severity.CRITICAL,
        status=FindingStatus.FAIL,
        category=Category.IDENTITY_ACCESS,
        description="Finding under test",
        dedup_keys=[key],
        benchmark_refs=["CIS M365 1.1.1"],
        raw_data={"tool": tool.value},
    )


def _make_consolidated(
    *,
    key: str = "cis:m365:1.1.1",
) -> ConsolidatedFinding:
    return ConsolidatedFinding(
        finding_instance_id="finding-001",
        finding_key=key,
        title=f"Consolidated {key}",
        severity=Severity.CRITICAL,
        status=FindingStatus.FAIL,
        category=Category.IDENTITY_ACCESS,
        description="Consolidated finding under test",
        sources=[
            SourceEvidence(
                tool=ToolSource.SCUBAGEAR,
                check_id="MS.AAD.3.1v1",
                raw_data={"result": "Fail"},
            )
        ],
        confidence=ConfidenceScore(
            evidence_strength=0.9,
            corroborating_tools=1,
            data_freshness=1.0,
            provenance="system-generated",
            overall=0.9,
        ),
        benchmark_refs=["CIS M365 1.1.1"],
    )


def _make_coverage_record(
    *,
    control_id: str = "CIS-1.1.1",
    tool: ToolSource = ToolSource.SCUBAGEAR,
    status: CoverageStatus = CoverageStatus.ASSESSED,
    reason: str | None = "Covered by adapter",
) -> CoverageRecord:
    return CoverageRecord(
        control_id=control_id,
        tool=tool,
        status=status,
        reason=reason,
    )


def _set_engagement_state(repo: MagicMock, state: EngagementState) -> None:
    repo.get.return_value = {
        "engagement_id": "eng-001",
        "client_name": "Test Client",
        "state": state.value,
        "config_snapshot": "{}",
    }


@dataclass
class RunnerHarness:
    orchestrator: Orchestrator
    engagement_repo: MagicMock
    event_repo: MagicMock
    finding_repo: MagicMock
    coverage_repo: MagicMock
    artifact_manager: MagicMock


@pytest.fixture
def harness() -> RunnerHarness:
    engagement_repo = MagicMock()
    _set_engagement_state(engagement_repo, EngagementState.CREATED)

    event_repo = MagicMock()
    event_repo.get_events_by_type.return_value = []

    finding_repo = MagicMock()
    coverage_repo = MagicMock()

    lock = MagicMock()
    lock.hold.return_value.__enter__ = MagicMock(return_value=None)
    lock.hold.return_value.__exit__ = MagicMock(return_value=False)

    artifact_manager = MagicMock()
    db = MagicMock()

    orchestrator = Orchestrator(
        engagement_repo=engagement_repo,
        event_repo=event_repo,
        finding_repo=finding_repo,
        coverage_repo=coverage_repo,
        lock=lock,
        db=db,
        artifact_manager=artifact_manager,
    )
    return RunnerHarness(
        orchestrator=orchestrator,
        engagement_repo=engagement_repo,
        event_repo=event_repo,
        finding_repo=finding_repo,
        coverage_repo=coverage_repo,
        artifact_manager=artifact_manager,
    )


class TestRunStagesResumePaths:
    def test_parse_resume_uses_rehydrated_results_and_persists_nonempty_coverage(
        self, harness: RunnerHarness
    ) -> None:
        _set_engagement_state(harness.engagement_repo, EngagementState.COLLECTED)
        adapter_results = [_make_adapter_result()]
        observations = [_make_observation()]
        coverage_records = [_make_coverage_record()]
        expected_rows = [
            {
                "control_id": "CIS-1.1.1",
                "tool_source": ToolSource.SCUBAGEAR.value,
                "status": CoverageStatus.ASSESSED.value,
                "reason": "Covered by adapter",
            }
        ]

        with (
            patch(
                "gxassessms.pipeline._runner._rehydrate_upstream_state",
                return_value=(adapter_results, None, None),
            ),
            patch("gxassessms.pipeline._runner.parse", return_value=observations) as mock_parse,
            patch(
                "gxassessms.pipeline._runner.collect_coverage",
                return_value=coverage_records,
            ) as mock_collect_coverage,
        ):
            run_stages(
                orchestrator=harness.orchestrator,
                engagement_id="eng-001",
                config=_make_config(),
                adapters=[],
                normalization_policy=MagicMock(),
                consolidation_rule=MagicMock(),
                qa_strategy=MagicMock(),
                renderers=[],
                start_stage=Stage.PARSE,
                stop_stage=Stage.PARSE,
            )

        mock_parse.assert_called_once_with(adapter_results, [])
        mock_collect_coverage.assert_called_once_with(adapter_results, [])
        assert harness.coverage_repo.method_calls == [
            call.delete_for_engagement("eng-001"),
            call.save("eng-001", expected_rows),
        ]

    def test_qa_review_non_noop_holds_before_render(self, harness: RunnerHarness) -> None:
        _set_engagement_state(harness.engagement_repo, EngagementState.CONSOLIDATED)
        consolidated = [_make_consolidated()]
        qa_strategy = MagicMock()
        qa_strategy.is_noop = False
        qa_results = [
            {
                "finding_instance_id": "finding-001",
                "adjusted_severity": None,
                "confidence_delta": 0.0,
                "narrative": None,
                "flags": ["manual-review"],
            }
        ]
        qa_strategy.review_findings.return_value = qa_results

        # Patch rehydration at the runner boundary so the resume-path behavior is explicit.
        with (
            patch(
                "gxassessms.pipeline._runner._rehydrate_upstream_state",
                return_value=(None, None, consolidated),
            ),
            patch("gxassessms.pipeline._runner.render") as mock_render,
        ):
            run_stages(
                orchestrator=harness.orchestrator,
                engagement_id="eng-001",
                config=_make_config(),
                adapters=[],
                normalization_policy=MagicMock(),
                consolidation_rule=MagicMock(),
                qa_strategy=qa_strategy,
                renderers=[],
                start_stage=Stage.QA_REVIEW,
            )

        qa_strategy.review_findings.assert_called_once_with(consolidated)
        assert harness.engagement_repo.update_state.call_args_list == [
            call("eng-001", EngagementState.QA_REVIEW)
        ]
        mock_render.assert_not_called()

    def test_render_resume_uses_rehydrated_consolidated_findings(
        self, harness: RunnerHarness, tmp_path: Path
    ) -> None:
        _set_engagement_state(harness.engagement_repo, EngagementState.QA_APPROVED)
        consolidated = [_make_consolidated()]
        report_dir = tmp_path / "reports"
        payload = object()

        with (
            patch(
                "gxassessms.pipeline._runner._rehydrate_upstream_state",
                return_value=(None, None, consolidated),
            ),
            patch(
                "gxassessms.pipeline._runner._build_report_payload",
                return_value=payload,
            ) as mock_build_payload,
            patch("gxassessms.pipeline._runner.render") as mock_render,
        ):
            run_stages(
                orchestrator=harness.orchestrator,
                engagement_id="eng-001",
                config=_make_config(),
                adapters=[],
                normalization_policy=MagicMock(),
                consolidation_rule=MagicMock(),
                qa_strategy=MagicMock(),
                renderers=[],
                start_stage=Stage.RENDER,
                output_dir=report_dir,
            )

        mock_build_payload.assert_called_once_with(
            "eng-001",
            _make_config(),
            consolidated,
            harness.orchestrator._coverage_repo,
        )
        mock_render.assert_called_once_with(payload, [], report_dir)
        assert report_dir.exists()


class TestRehydrateHelpers:
    def test_qa_review_rehydration_returns_consolidated_findings(
        self, harness: RunnerHarness
    ) -> None:
        consolidated = [_make_consolidated()]
        harness.event_repo.get_events_by_type.return_value = [{"payload": '{"to": "CONSOLIDATED"}'}]
        harness.finding_repo.get_consolidated_as_findings.return_value = consolidated

        adapter_results, findings, rehydrated = _rehydrate_upstream_state(
            Stage.QA_REVIEW, "eng-001", [], harness.orchestrator
        )

        assert adapter_results is None
        assert findings is None
        assert rehydrated == consolidated
        harness.finding_repo.get_consolidated_as_findings.assert_called_once_with("eng-001")

    def test_recover_stale_state_rejects_unknown_state(self, harness: RunnerHarness) -> None:
        bogus_state = SimpleNamespace(value="BOGUS")

        with pytest.raises(PipelineError, match="unrecognized stale state: BOGUS"):
            _recover_stale_state(harness.orchestrator, "eng-001", bogus_state)

        harness.engagement_repo.force_update_state.assert_not_called()


class TestInMemoryGuards:
    def test_require_in_memory_raises_for_none(self) -> None:
        with pytest.raises(PipelineError, match="requires observations"):
            _require_in_memory("observations", None, Stage.NORMALIZE)

    def test_require_in_memory_allows_empty_list(self) -> None:
        assert _require_in_memory("observations", [], Stage.NORMALIZE) is None


class TestAdapterMapMerging:
    def test_merge_adapter_map_resolves_enum_values_and_skips_missing_mappings(self) -> None:
        adapters = [
            SimpleNamespace(),
            SimpleNamespace(category_map={"MS.AAD": Category.IDENTITY_ACCESS, "plain": "literal"}),
        ]

        result = _merge_adapter_map(adapters, "category_map")

        assert result == {
            "MS.AAD": Category.IDENTITY_ACCESS.value,
            "plain": "literal",
        }

    def test_merge_adapter_map_preserves_values_when_resolve_enum_false_and_warns(self) -> None:
        adapters = [
            SimpleNamespace(dedup_key_rules={"MS.AAD.3.1v1": Severity.HIGH}),
            SimpleNamespace(dedup_key_rules={"MS.AAD.3.1v1": Severity.CRITICAL}),
        ]

        with patch("gxassessms.pipeline._runner.logger.warning") as mock_warning:
            result = _merge_adapter_map(adapters, "dedup_key_rules", resolve_enum=False)

        assert result == {"MS.AAD.3.1v1": Severity.CRITICAL}
        mock_warning.assert_called_once_with(
            "%s key %s: %s -> %s",
            "dedup_key_rules",
            "MS.AAD.3.1v1",
            Severity.HIGH,
            Severity.CRITICAL,
        )


class TestReportPayloadBridge:
    def test_build_report_payload_wraps_in_memory_repos(self) -> None:
        config = _make_config()
        consolidated = [_make_consolidated()]
        coverage_repo = MagicMock()
        coverage_rows = [{"control_id": "CIS-1.1.1", "status": "assessed"}]
        coverage_repo.get_for_engagement.return_value = coverage_rows
        sentinel_payload = object()
        fake_now = object()
        fake_reporting_pkg = ModuleType("gxassessms.reporting")
        fake_reporting_pkg.__path__ = []
        fake_payload_module = ModuleType("gxassessms.reporting.payload")
        mock_assemble = MagicMock(return_value=sentinel_payload)
        fake_payload_module.assemble_payload = mock_assemble

        with (
            patch("gxassessms.pipeline._runner.utc_now", return_value=fake_now),
            patch(
                "gxassessms.pipeline._runner.format_utc",
                return_value="2026-04-03T10:00:00Z",
            ) as mock_format_utc,
            patch.dict(
                sys.modules,
                {
                    "gxassessms.reporting": fake_reporting_pkg,
                    "gxassessms.reporting.payload": fake_payload_module,
                },
            ),
        ):
            result = _build_report_payload("eng-001", config, consolidated, coverage_repo)

        assert result is sentinel_payload
        mock_format_utc.assert_called_once_with(fake_now)
        assemble_kwargs = mock_assemble.call_args.kwargs
        assert assemble_kwargs["engagement_id"] == "eng-001"
        assert assemble_kwargs["tenant_name"] == "Test Client"
        assert assemble_kwargs["assessment_date"] == "2026-04-03T10:00:00Z"
        assert assemble_kwargs["tool_sources"] == ["scubagear", "maester"]
        assert assemble_kwargs["config_snapshot"] == config.model_dump()

        finding_repo = assemble_kwargs["finding_repo"]
        wrapped_coverage_repo = assemble_kwargs["coverage_repo"]
        assert finding_repo.get_consolidated("eng-001") == [consolidated[0].model_dump()]
        assert wrapped_coverage_repo.get_for_engagement("eng-001") == coverage_rows
        coverage_repo.get_for_engagement.assert_called_once_with("eng-001")


def _expected_stage_output(
    stage: Stage,
    *,
    adapter_result: AdapterResult,
    observation: ToolObservation,
    finding: Finding,
    consolidated: ConsolidatedFinding,
    qa_results: list[dict[str, object]],
) -> list[object]:
    if stage == Stage.COLLECT:
        return [adapter_result.model_dump()]
    if stage == Stage.PARSE:
        return [observation.model_dump()]
    if stage == Stage.NORMALIZE:
        return [finding.model_dump()]
    if stage == Stage.CONSOLIDATE:
        return [consolidated.model_dump()]
    if stage == Stage.QA_REVIEW:
        return qa_results
    return []


class TestGetStageOutput:
    @pytest.mark.parametrize(
        "stage",
        [
            Stage.COLLECT,
            Stage.PARSE,
            Stage.NORMALIZE,
            Stage.CONSOLIDATE,
            Stage.QA_REVIEW,
            Stage.RENDER,
        ],
    )
    def test_returns_serializable_output_for_each_stage(self, stage: Stage) -> None:
        adapter_result = _make_adapter_result()
        observation = _make_observation()
        finding = _make_finding()
        consolidated = _make_consolidated()
        qa_results = [{"finding_instance_id": "finding-001", "flags": ["manual-review"]}]

        result = _get_stage_output(
            stage,
            adapter_results=[adapter_result],
            observations=[observation],
            findings=[finding],
            consolidated_findings=[consolidated],
            qa_results=qa_results,
        )

        assert result == _expected_stage_output(
            stage,
            adapter_result=adapter_result,
            observation=observation,
            finding=finding,
            consolidated=consolidated,
            qa_results=qa_results,
        )

    def test_raises_for_invalid_stage(self) -> None:
        # Use a minimal fake stage so this trips the runner guard instead of enum construction.
        invalid_stage = SimpleNamespace(value="UNKNOWN_STAGE")

        with pytest.raises(ValueError, match="Unhandled stage for hashing: UNKNOWN_STAGE"):
            _get_stage_output(
                invalid_stage,
                adapter_results=[],
                observations=[],
                findings=[],
                consolidated_findings=[],
                qa_results=[],
            )


class TestFailureFallbacks:
    def test_pipeline_error_preserves_original_error_when_failed_transition_also_fails(
        self, harness: RunnerHarness
    ) -> None:
        _set_engagement_state(harness.engagement_repo, EngagementState.COLLECTED)

        with (
            patch(
                "gxassessms.pipeline._runner._rehydrate_upstream_state",
                return_value=(None, None, None),
            ),
            patch.object(
                harness.orchestrator,
                "_transition_state",
                side_effect=[None, RuntimeError("db unavailable")],
            ),
            patch("gxassessms.pipeline._runner.logger.error") as mock_log_error,
            pytest.raises(PipelineError, match="requires adapter_results"),
        ):
            run_stages(
                orchestrator=harness.orchestrator,
                engagement_id="eng-001",
                config=_make_config(),
                adapters=[],
                normalization_policy=MagicMock(),
                consolidation_rule=MagicMock(),
                qa_strategy=MagicMock(),
                renderers=[],
                start_stage=Stage.PARSE,
            )

        mock_log_error.assert_called_once_with(
            "Failed to transition %s to FAILED", "eng-001", exc_info=True
        )

    def test_generic_stage_error_wraps_as_pipeline_error_even_if_failed_transition_fails(
        self, harness: RunnerHarness
    ) -> None:
        _set_engagement_state(harness.engagement_repo, EngagementState.COLLECTED)
        adapter_results = [_make_adapter_result()]

        with (
            patch(
                "gxassessms.pipeline._runner._rehydrate_upstream_state",
                return_value=(adapter_results, None, None),
            ),
            patch("gxassessms.pipeline._runner.parse", side_effect=ValueError("bad parse")),
            patch.object(
                harness.orchestrator,
                "_transition_state",
                side_effect=[None, RuntimeError("db unavailable")],
            ),
            patch("gxassessms.pipeline._runner.logger.error") as mock_log_error,
            pytest.raises(PipelineError, match="Stage PARSE failed: bad parse"),
        ):
            run_stages(
                orchestrator=harness.orchestrator,
                engagement_id="eng-001",
                config=_make_config(),
                adapters=[],
                normalization_policy=MagicMock(),
                consolidation_rule=MagicMock(),
                qa_strategy=MagicMock(),
                renderers=[],
                start_stage=Stage.PARSE,
            )

        first_call, second_call = mock_log_error.call_args_list
        assert first_call.args[:3] == (
            "Stage %s failed for engagement %s: %s",
            "PARSE",
            "eng-001",
        )
        assert isinstance(first_call.args[3], ValueError)
        assert str(first_call.args[3]) == "bad parse"
        assert second_call == call("Failed to transition %s to FAILED", "eng-001", exc_info=True)
