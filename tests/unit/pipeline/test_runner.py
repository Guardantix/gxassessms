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
from gxassessms.core.contracts.errors import PipelineError, ReportError
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
    ArtifactRecord,
    CollectedArtifact,
    CollectionOutput,
    CollectionResult,
    ConfidenceScore,
    ConsolidatedFinding,
    CoverageRecord,
    Finding,
    ResolvedManifest,
    SourceEvidence,
    ToolObservation,
)
from gxassessms.pipeline._runner import (
    StageContext,
    _build_report_payload,
    _describe_renderers,
    _filter_renderers,
    _get_stage_output,
    _handle_qa_completion,
    _merge_adapter_map,
    _recover_stale_state,
    _rehydrate_upstream_state,
    _require_in_memory,
    _run_collect,
    _run_consolidate,
    _run_normalize,
    _run_parse,
    _run_qa_review,
    _run_render,
    _verify_stage_completed,
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


def _make_raw_output(tool: ToolSource = ToolSource.SCUBAGEAR) -> ResolvedManifest:
    slug = tool.value.lower()
    return ResolvedManifest(
        tool=tool,
        tool_slug=slug,
        schema_version="1.0.0",
        manifest_version="1.0.0",
        timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
        file_manifest={
            f"{slug}/results.json": ArtifactRecord(encoding="utf-8", sha256="a" * 64),
        },
        execution_metadata={"exit_code": 0},
    )


def _make_collection_result(
    *,
    adapter_name: str = "scubagear",
    tool: ToolSource = ToolSource.SCUBAGEAR,
) -> CollectionResult:
    slug = tool.value.lower()
    return CollectionResult(
        adapter_name=adapter_name,
        status=AdapterRunStatus.SUCCESS,
        collection_output=CollectionOutput(
            tool=tool,
            tool_slug=slug,
            schema_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            artifacts=[
                CollectedArtifact(
                    source_path="/var/data/results.json",
                    target_relpath=f"{slug}/results.json",
                    encoding="utf-8",
                    sha256="a" * 64,
                ),
            ],
            execution_metadata={"exit_code": 0},
        ),
        error=None,
        duration_seconds=1.25,
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

    def run(
        self,
        *,
        start_stage: Stage,
        stop_stage: Stage | None = None,
        qa_strategy: object | None = None,
        output_dir: Path | None = None,
    ) -> None:
        """Shorthand for run_stages with common defaults."""
        run_stages(
            orchestrator=self.orchestrator,
            engagement_id="eng-001",
            config=_make_config(),
            adapters=[],
            normalization_policy=MagicMock(),
            consolidation_rule=MagicMock(),
            qa_strategy=qa_strategy if qa_strategy is not None else MagicMock(),
            renderers=[],
            start_stage=start_stage,
            stop_stage=stop_stage,
            output_dir=output_dir,
        )


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
        # Rehydration returns loaded manifests (opaque to this test).
        loaded_manifests = [MagicMock()]
        # confine_and_resolve produces ResolvedManifest objects.
        resolved = [_make_raw_output()]
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
                return_value=(loaded_manifests, None, None),
            ),
            patch(
                "gxassessms.pipeline.confinement.confine_and_resolve",
                return_value=resolved,
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

        # The runner wraps resolved manifests in AdapterResult before passing
        # to parse/collect_coverage.
        actual_adapter_results = mock_parse.call_args.args[0]
        assert len(actual_adapter_results) == 1
        assert actual_adapter_results[0].raw_output == resolved[0]
        mock_collect_coverage.assert_called_once()
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
            patch("gxassessms.pipeline._runner._filter_renderers", return_value=[]),
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

    def test_render_stage_defaults_to_engagement_reports_dir(
        self, harness: RunnerHarness, tmp_path: Path
    ) -> None:
        """When output_dir is None, report_dir defaults to engagement_dir/reports/."""
        _set_engagement_state(harness.engagement_repo, EngagementState.QA_APPROVED)
        eng_dir = tmp_path / "acme-eng-001"
        eng_dir.mkdir()
        (eng_dir / "reports").mkdir()
        harness.artifact_manager.get_engagement_dir.return_value = eng_dir
        consolidated = [_make_consolidated()]
        payload = object()

        with (
            patch(
                "gxassessms.pipeline._runner._rehydrate_upstream_state",
                return_value=(None, None, consolidated),
            ),
            patch(
                "gxassessms.pipeline._runner._build_report_payload",
                return_value=payload,
            ),
            patch("gxassessms.pipeline._runner._filter_renderers", return_value=[]),
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
                # output_dir intentionally omitted -- should default to eng_dir/reports
            )

        mock_render.assert_called_once_with(payload, [], eng_dir / "reports")


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

    def test_merge_adapter_map_single_adapter_does_not_collide(self) -> None:
        """Per-tool category maps built from a single adapter avoid cross-tool collisions.

        ScubaGear maps "defender" -> EMAIL_COLLABORATION (M365 Defender for Office 365).
        Prowler maps "defender" -> INFRASTRUCTURE_SECURITY (Azure Defender for Cloud).
        A flat-merged map would let one overwrite the other.  Building per-tool maps
        via _merge_adapter_map([adapter]) keeps each tool's mapping isolated.
        """
        scubagear_adapter = SimpleNamespace(
            tool_source=ToolSource.SCUBAGEAR,
            category_map={"defender": Category.EMAIL_COLLABORATION},
        )
        prowler_adapter = SimpleNamespace(
            tool_source=ToolSource.PROWLER,
            category_map={"defender": Category.INFRASTRUCTURE_SECURITY},
        )

        scuba_map = _merge_adapter_map([scubagear_adapter], "category_map")
        prowler_map = _merge_adapter_map([prowler_adapter], "category_map")

        assert scuba_map["defender"] == Category.EMAIL_COLLABORATION.value
        assert prowler_map["defender"] == Category.INFRASTRUCTURE_SECURITY.value
        # The two per-tool maps are independent -- no collision.
        assert scuba_map["defender"] != prowler_map["defender"]


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
    collection_result: CollectionResult,
    adapter_result: AdapterResult,
    observation: ToolObservation,
    finding: Finding,
    consolidated: ConsolidatedFinding,
    qa_results: list[dict[str, object]],
) -> list[object]:
    if stage == Stage.COLLECT:
        return [collection_result.model_dump()]
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
        collection_result = _make_collection_result()
        adapter_result = _make_adapter_result()
        observation = _make_observation()
        finding = _make_finding()
        consolidated = _make_consolidated()
        qa_results = [{"finding_instance_id": "finding-001", "flags": ["manual-review"]}]

        ctx = StageContext(
            collection_results=[collection_result],
            adapter_results=[adapter_result],
            observations=[observation],
            findings=[finding],
            consolidated_findings=[consolidated],
            qa_results=qa_results,
        )
        result = _get_stage_output(stage, ctx)

        assert result == _expected_stage_output(
            stage,
            collection_result=collection_result,
            adapter_result=adapter_result,
            observation=observation,
            finding=finding,
            consolidated=consolidated,
            qa_results=qa_results,
        )

    def test_raises_for_invalid_stage(self) -> None:
        # Use a minimal fake stage so this trips the runner guard instead of enum construction.
        invalid_stage = SimpleNamespace(value="UNKNOWN_STAGE")
        ctx = StageContext()

        with pytest.raises(ValueError, match="Unhandled stage for hashing: UNKNOWN_STAGE"):
            _get_stage_output(invalid_stage, ctx)


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
            pytest.raises(PipelineError, match="requires loaded_manifests"),
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
        loaded_manifests = [MagicMock()]

        with (
            patch(
                "gxassessms.pipeline._runner._rehydrate_upstream_state",
                return_value=(loaded_manifests, None, None),
            ),
            patch(
                "gxassessms.pipeline.confinement.confine_and_resolve",
                return_value=[_make_raw_output()],
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


class TestStopStageGuard:
    def test_stop_stage_qa_review_raises(self, harness: RunnerHarness) -> None:
        with pytest.raises(ValueError, match=r"stop_stage=Stage\.QA_REVIEW is not supported"):
            harness.run(start_stage=Stage.COLLECT, stop_stage=Stage.QA_REVIEW)
        harness.engagement_repo.update_state.assert_not_called()


class TestRehydrateEntries:
    def test_collect_returns_nones(self, harness: RunnerHarness) -> None:
        result = _rehydrate_upstream_state(Stage.COLLECT, "eng-001", [], harness.orchestrator)
        assert result == (None, None, None)

    def test_normalize_raises(self, harness: RunnerHarness) -> None:
        with pytest.raises(PipelineError, match="Cannot resume from NORMALIZE") as exc_info:
            _rehydrate_upstream_state(Stage.NORMALIZE, "eng-001", [], harness.orchestrator)
        assert "CONSOLIDATE" in str(exc_info.value)
        assert "PARSE" in str(exc_info.value)

    def test_parse_loads_manifests(self, harness: RunnerHarness) -> None:
        sentinel = MagicMock()
        harness.artifact_manager.get_engagement_dir.return_value = Path("/fake/eng")
        with patch(
            "gxassessms.pipeline.replay.load_raw_outputs", return_value=[sentinel]
        ) as mock_load:
            result = _rehydrate_upstream_state(Stage.PARSE, "eng-001", [], harness.orchestrator)
        assert result == ([sentinel], None, None)
        mock_load.assert_called_once_with(Path("/fake/eng"))

    def test_consolidate_loads_findings(self, harness: RunnerHarness) -> None:
        findings = [_make_finding()]
        harness.event_repo.get_events_by_type.return_value = [{"payload": '{"to": "NORMALIZED"}'}]
        harness.finding_repo.get_parsed_as_findings.return_value = findings
        result = _rehydrate_upstream_state(Stage.CONSOLIDATE, "eng-001", [], harness.orchestrator)
        assert result == (None, findings, None)
        harness.finding_repo.get_parsed_as_findings.assert_called_once_with("eng-001")

    def test_render_verifies_qa(self, harness: RunnerHarness) -> None:
        consolidated = [_make_consolidated()]
        harness.finding_repo.get_consolidated_as_findings.return_value = consolidated
        with patch.object(harness.orchestrator, "_verify_qa_for_render") as mock_verify:
            result = _rehydrate_upstream_state(Stage.RENDER, "eng-001", [], harness.orchestrator)
        assert result == (None, None, consolidated)
        mock_verify.assert_called_once_with("eng-001")

    def test_unhandled_stage_raises(self, harness: RunnerHarness) -> None:
        bogus_stage = SimpleNamespace(value="FUTURE_STAGE")
        with pytest.raises(PipelineError, match="Unhandled start_stage"):
            _rehydrate_upstream_state(bogus_stage, "eng-001", [], harness.orchestrator)


class TestVerifyStageCompleted:
    def test_succeeds_when_state_in_events(self, harness: RunnerHarness) -> None:
        harness.event_repo.get_events_by_type.return_value = [{"payload": '{"to": "NORMALIZED"}'}]
        _verify_stage_completed(harness.orchestrator, "eng-001", EngagementState.NORMALIZED)

    def test_raises_when_state_missing(self, harness: RunnerHarness) -> None:
        harness.event_repo.get_events_by_type.return_value = [{"payload": '{"to": "COLLECTED"}'}]
        with pytest.raises(PipelineError, match="upstream stage never completed"):
            _verify_stage_completed(harness.orchestrator, "eng-001", EngagementState.NORMALIZED)


class TestRecoverStaleStateSuccess:
    def test_recovers_to_entry_state(self, harness: RunnerHarness) -> None:
        result = _recover_stale_state(harness.orchestrator, "eng-001", EngagementState.COLLECTING)
        assert result == Stage.COLLECT
        harness.engagement_repo.force_update_state.assert_called_once_with(
            "eng-001", EngagementState.CREATED
        )
        event = harness.event_repo.append.call_args.args[0]
        assert event.event_type == "stale_recovery"
        assert event.payload["from"] == "COLLECTING"
        assert event.payload["to"] == "CREATED"
        assert "Stale" in event.payload["reason"]


class TestStageIntegration:
    def test_collect_stop_stage_halts_after_collect(self, harness: RunnerHarness) -> None:
        _set_engagement_state(harness.engagement_repo, EngagementState.CREATED)
        collection_results = [_make_collection_result()]
        raw_outputs = [_make_raw_output()]
        harness.artifact_manager.save_raw_outputs.return_value = raw_outputs

        with (
            patch(
                "gxassessms.pipeline._runner.collect",
                return_value=collection_results,
            ) as mock_collect,
            patch(
                "gxassessms.pipeline._runner._rehydrate_upstream_state",
                return_value=(None, None, None),
            ),
            patch("gxassessms.pipeline._runner.parse") as mock_parse,
        ):
            harness.run(start_stage=Stage.COLLECT, stop_stage=Stage.COLLECT)

        mock_collect.assert_called_once()
        harness.artifact_manager.save_raw_outputs.assert_called_once()
        mock_parse.assert_not_called()
        state_calls = [c.args[1] for c in harness.engagement_repo.update_state.call_args_list]
        assert EngagementState.COLLECTING in state_calls
        assert EngagementState.COLLECTED in state_calls

    def test_parse_resume_with_empty_coverage_skips_save(self, harness: RunnerHarness) -> None:
        _set_engagement_state(harness.engagement_repo, EngagementState.COLLECTED)
        loaded_manifests = [MagicMock()]
        resolved = [_make_raw_output()]

        with (
            patch(
                "gxassessms.pipeline._runner._rehydrate_upstream_state",
                return_value=(loaded_manifests, None, None),
            ),
            patch(
                "gxassessms.pipeline.confinement.confine_and_resolve",
                return_value=resolved,
            ),
            patch(
                "gxassessms.pipeline._runner.parse",
                return_value=[_make_observation()],
            ),
            patch(
                "gxassessms.pipeline._runner.collect_coverage",
                return_value=[],
            ),
        ):
            harness.run(start_stage=Stage.PARSE, stop_stage=Stage.PARSE)

        harness.coverage_repo.delete_for_engagement.assert_called_once_with("eng-001")
        harness.coverage_repo.save.assert_not_called()

    def test_noop_qa_auto_advances_through_to_render(
        self, harness: RunnerHarness, tmp_path: Path
    ) -> None:
        _set_engagement_state(harness.engagement_repo, EngagementState.CONSOLIDATED)
        consolidated = [_make_consolidated()]
        qa_strategy = MagicMock(is_noop=True, review_findings=MagicMock(return_value=[]))

        with (
            patch(
                "gxassessms.pipeline._runner._rehydrate_upstream_state",
                return_value=(None, None, consolidated),
            ),
            patch(
                "gxassessms.pipeline._runner._build_report_payload",
                return_value=MagicMock(),
            ),
            patch("gxassessms.pipeline._runner._filter_renderers", return_value=[]),
            patch("gxassessms.pipeline._runner.render") as mock_render,
        ):
            harness.run(start_stage=Stage.QA_REVIEW, qa_strategy=qa_strategy, output_dir=tmp_path)

        qa_strategy.review_findings.assert_called_once_with(consolidated)
        state_calls = [c.args[1] for c in harness.engagement_repo.update_state.call_args_list]
        assert EngagementState.QA_REVIEW in state_calls
        assert EngagementState.QA_APPROVED in state_calls
        assert EngagementState.RENDERING in state_calls
        assert EngagementState.COMPLETE in state_calls
        mock_render.assert_called_once()

    def test_parse_through_consolidate_exercises_normalize_and_consolidate(
        self, harness: RunnerHarness
    ) -> None:
        _set_engagement_state(harness.engagement_repo, EngagementState.COLLECTED)
        loaded_manifests = [MagicMock()]
        resolved = [_make_raw_output()]
        observations = [_make_observation()]
        findings = [_make_finding()]
        consolidated = [_make_consolidated()]

        with (
            patch(
                "gxassessms.pipeline._runner._rehydrate_upstream_state",
                return_value=(loaded_manifests, None, None),
            ),
            patch(
                "gxassessms.pipeline.confinement.confine_and_resolve",
                return_value=resolved,
            ),
            patch("gxassessms.pipeline._runner.parse", return_value=observations),
            patch("gxassessms.pipeline._runner.collect_coverage", return_value=[]),
            patch(
                "gxassessms.pipeline._runner.normalize",
                return_value=findings,
            ) as mock_normalize,
            patch(
                "gxassessms.pipeline._runner.consolidate",
                return_value=consolidated,
            ) as mock_consolidate,
        ):
            harness.run(start_stage=Stage.PARSE, stop_stage=Stage.CONSOLIDATE)

        mock_normalize.assert_called_once()
        norm_args = mock_normalize.call_args
        assert norm_args.args[0] == observations
        assert "adapter_severity_map" in norm_args.kwargs

        mock_consolidate.assert_called_once()
        assert mock_consolidate.call_args.args[0] == findings

        harness.finding_repo.save_parsed_findings.assert_called_once_with("eng-001", findings)
        harness.finding_repo.save_consolidated_findings.assert_called_once_with(
            "eng-001", consolidated
        )

        state_calls = [c.args[1] for c in harness.engagement_repo.update_state.call_args_list]
        assert EngagementState.PARSING in state_calls
        assert EngagementState.NORMALIZING in state_calls
        assert EngagementState.CONSOLIDATED in state_calls


# ---------------------------------------------------------------------------
# Direct handler tests (commit 2)
# ---------------------------------------------------------------------------


class TestRunCollect:
    def test_populates_ctx_and_persists_raw_outputs(self, harness: RunnerHarness) -> None:
        collection_results = [_make_collection_result()]
        loaded_manifests = [MagicMock()]
        harness.artifact_manager.save_raw_outputs.return_value = loaded_manifests
        ctx = StageContext()

        with patch("gxassessms.pipeline._runner.collect", return_value=collection_results):
            _run_collect(ctx, _make_config(), [], harness.orchestrator, "eng-001")

        assert ctx.collection_results == collection_results
        assert ctx.loaded_manifests == loaded_manifests
        harness.artifact_manager.save_raw_outputs.assert_called_once_with(
            "eng-001", "Test Client", collection_results
        )

    def test_empty_adapters_still_calls_save(self, harness: RunnerHarness) -> None:
        harness.artifact_manager.save_raw_outputs.return_value = []
        ctx = StageContext()

        with patch("gxassessms.pipeline._runner.collect", return_value=[]):
            _run_collect(ctx, _make_config(), [], harness.orchestrator, "eng-001")

        assert ctx.collection_results == []
        assert ctx.loaded_manifests == []
        harness.artifact_manager.save_raw_outputs.assert_called_once()


class TestRunParse:
    def test_raises_when_loaded_manifests_is_none(self, harness: RunnerHarness) -> None:
        ctx = StageContext()  # loaded_manifests defaults to None
        with pytest.raises(PipelineError, match="requires loaded_manifests"):
            _run_parse(ctx, [], harness.orchestrator, "eng-001")

    def test_wraps_resolved_in_adapter_results_and_sets_observations(
        self, harness: RunnerHarness
    ) -> None:
        resolved = [_make_raw_output()]
        observations = [_make_observation()]
        ctx = StageContext(loaded_manifests=[MagicMock()])
        harness.artifact_manager.get_engagement_dir.return_value = Path("/fake/eng")

        with (
            patch("gxassessms.pipeline.confinement.confine_and_resolve", return_value=resolved),
            patch("gxassessms.pipeline._runner.parse", return_value=observations),
            patch("gxassessms.pipeline._runner.collect_coverage", return_value=[]),
        ):
            _run_parse(ctx, [], harness.orchestrator, "eng-001")

        assert ctx.observations == observations
        assert len(ctx.adapter_results) == 1
        assert ctx.adapter_results[0].status == AdapterRunStatus.SUCCESS
        assert ctx.adapter_results[0].duration_seconds == 0.0
        assert ctx.adapter_results[0].raw_output == resolved[0]

    def test_coverage_persisted_when_nonempty(self, harness: RunnerHarness) -> None:
        coverage = [_make_coverage_record()]
        ctx = StageContext(loaded_manifests=[MagicMock()])
        harness.artifact_manager.get_engagement_dir.return_value = Path("/fake/eng")

        with (
            patch(
                "gxassessms.pipeline.confinement.confine_and_resolve",
                return_value=[_make_raw_output()],
            ),
            patch("gxassessms.pipeline._runner.parse", return_value=[]),
            patch("gxassessms.pipeline._runner.collect_coverage", return_value=coverage),
        ):
            _run_parse(ctx, [], harness.orchestrator, "eng-001")

        harness.coverage_repo.delete_for_engagement.assert_called_once_with("eng-001")
        harness.coverage_repo.save.assert_called_once()

    def test_empty_coverage_skips_save(self, harness: RunnerHarness) -> None:
        ctx = StageContext(loaded_manifests=[MagicMock()])
        harness.artifact_manager.get_engagement_dir.return_value = Path("/fake/eng")

        with (
            patch(
                "gxassessms.pipeline.confinement.confine_and_resolve",
                return_value=[_make_raw_output()],
            ),
            patch("gxassessms.pipeline._runner.parse", return_value=[]),
            patch("gxassessms.pipeline._runner.collect_coverage", return_value=[]),
        ):
            _run_parse(ctx, [], harness.orchestrator, "eng-001")

        harness.coverage_repo.delete_for_engagement.assert_called_once()
        harness.coverage_repo.save.assert_not_called()


class TestRunNormalize:
    def test_raises_when_observations_is_none(self, harness: RunnerHarness) -> None:
        ctx = StageContext()
        with pytest.raises(PipelineError, match="requires observations"):
            _run_normalize(ctx, [], MagicMock(), harness.orchestrator, "eng-001")

    def test_sets_findings_and_persists(self, harness: RunnerHarness) -> None:
        findings = [_make_finding()]
        ctx = StageContext(observations=[_make_observation()])

        with patch("gxassessms.pipeline._runner.normalize", return_value=findings):
            _run_normalize(ctx, [], MagicMock(), harness.orchestrator, "eng-001")

        assert ctx.findings == findings
        harness.finding_repo.save_parsed_findings.assert_called_once_with("eng-001", findings)

    def test_groups_observations_by_tool_and_normalizes_per_group(
        self, harness: RunnerHarness
    ) -> None:
        obs_scuba = _make_observation(tool=ToolSource.SCUBAGEAR, check_id="MS.AAD.1")
        obs_prowler = _make_observation(tool=ToolSource.PROWLER, check_id="prowler-1")
        ctx = StageContext(observations=[obs_scuba, obs_prowler])

        with patch("gxassessms.pipeline._runner.normalize", return_value=[]) as mock_norm:
            _run_normalize(ctx, [], MagicMock(), harness.orchestrator, "eng-001")

        assert mock_norm.call_count == 2
        # Each call gets only its tool's observations
        call_obs_lists = [c.args[0] for c in mock_norm.call_args_list]
        assert any(obs_scuba in obs_list for obs_list in call_obs_lists)
        assert any(obs_prowler in obs_list for obs_list in call_obs_lists)
        assert not any(
            obs_scuba in obs_list and obs_prowler in obs_list for obs_list in call_obs_lists
        )


class TestRunConsolidate:
    def test_raises_when_findings_is_none(self, harness: RunnerHarness) -> None:
        ctx = StageContext()
        with pytest.raises(PipelineError, match="requires findings"):
            _run_consolidate(ctx, MagicMock(), harness.orchestrator, "eng-001")

    def test_sets_consolidated_and_persists(self, harness: RunnerHarness) -> None:
        consolidated = [_make_consolidated()]
        rule = MagicMock()
        rule.consolidate.return_value = consolidated
        ctx = StageContext(findings=[_make_finding()])

        _run_consolidate(ctx, rule, harness.orchestrator, "eng-001")

        assert ctx.consolidated_findings == consolidated
        harness.finding_repo.save_consolidated_findings.assert_called_once_with(
            "eng-001", consolidated
        )


class TestRunQaReview:
    def test_raises_when_consolidated_is_none(self) -> None:
        ctx = StageContext()
        with pytest.raises(PipelineError, match="requires consolidated_findings"):
            _run_qa_review(ctx, MagicMock())

    def test_sets_qa_results(self) -> None:
        qa_results = [{"finding_instance_id": "f-1", "flags": []}]
        strategy = MagicMock()
        strategy.review_findings.return_value = qa_results
        consolidated = [_make_consolidated()]
        ctx = StageContext(consolidated_findings=consolidated)

        _run_qa_review(ctx, strategy)

        assert ctx.qa_results == qa_results
        strategy.review_findings.assert_called_once_with(consolidated)


class TestRunRender:
    def test_raises_when_consolidated_is_none(self, harness: RunnerHarness) -> None:
        ctx = StageContext()
        with pytest.raises(PipelineError, match="requires consolidated_findings"):
            _run_render(ctx, [], None, _make_config(), "eng-001", harness.orchestrator)

    def test_uses_provided_output_dir(self, harness: RunnerHarness, tmp_path: Path) -> None:
        ctx = StageContext(consolidated_findings=[_make_consolidated()])

        with (
            patch(
                "gxassessms.pipeline._runner._build_report_payload",
                return_value=MagicMock(),
            ) as mock_build,
            patch("gxassessms.pipeline._runner._filter_renderers", return_value=[]),
            patch("gxassessms.pipeline._runner.render") as mock_render,
        ):
            _run_render(ctx, [], tmp_path, _make_config(), "eng-001", harness.orchestrator)

        mock_render.assert_called_once_with(mock_build.return_value, [], tmp_path)

    def test_defaults_to_engagement_reports_dir(
        self, harness: RunnerHarness, tmp_path: Path
    ) -> None:
        eng_dir = tmp_path / "acme-eng-001"
        eng_dir.mkdir()
        harness.artifact_manager.get_engagement_dir.return_value = eng_dir
        ctx = StageContext(consolidated_findings=[_make_consolidated()])

        with (
            patch(
                "gxassessms.pipeline._runner._build_report_payload",
                return_value=MagicMock(),
            ) as mock_build,
            patch("gxassessms.pipeline._runner._filter_renderers", return_value=[]),
            patch("gxassessms.pipeline._runner.render") as mock_render,
        ):
            _run_render(ctx, [], None, _make_config(), "eng-001", harness.orchestrator)

        mock_render.assert_called_once_with(mock_build.return_value, [], eng_dir / "reports")

    def test_builds_payload_with_correct_args(self, harness: RunnerHarness, tmp_path: Path) -> None:
        consolidated = [_make_consolidated()]
        config = _make_config()
        ctx = StageContext(consolidated_findings=consolidated)

        with (
            patch(
                "gxassessms.pipeline._runner._build_report_payload",
                return_value=MagicMock(),
            ) as mock_build,
            patch("gxassessms.pipeline._runner._filter_renderers", return_value=[]),
            patch("gxassessms.pipeline._runner.render"),
        ):
            _run_render(ctx, [], tmp_path, config, "eng-001", harness.orchestrator)

        mock_build.assert_called_once_with(
            "eng-001", config, consolidated, harness.orchestrator._coverage_repo
        )


class TestHandleQaCompletion:
    def test_noop_transitions_and_returns_continue(self) -> None:
        orch = MagicMock()
        strategy = MagicMock(is_noop=True)

        state, should_break = _handle_qa_completion(
            orch,
            "eng-001",
            strategy,
            EngagementState.QA_REVIEW,
            EngagementState.QA_APPROVED,
            "abc123",
        )

        assert state == EngagementState.QA_APPROVED
        assert should_break is False
        orch._transition_state.assert_called_once_with(
            "eng-001",
            EngagementState.QA_REVIEW,
            EngagementState.QA_APPROVED,
            content_hash="abc123",
        )

    def test_non_noop_holds_and_returns_break(self) -> None:
        orch = MagicMock()
        strategy = MagicMock(is_noop=False)

        state, should_break = _handle_qa_completion(
            orch,
            "eng-001",
            strategy,
            EngagementState.QA_REVIEW,
            EngagementState.QA_APPROVED,
            "abc123",
        )

        assert state == EngagementState.QA_REVIEW
        assert should_break is True
        orch._transition_state.assert_not_called()

    def test_missing_is_noop_treated_as_non_noop(self) -> None:
        orch = MagicMock()
        strategy = MagicMock(spec=[])  # no attributes at all

        state, should_break = _handle_qa_completion(
            orch,
            "eng-001",
            strategy,
            EngagementState.QA_REVIEW,
            EngagementState.QA_APPROVED,
            "abc123",
        )

        assert state == EngagementState.QA_REVIEW
        assert should_break is True
        orch._transition_state.assert_not_called()


# ---------------------------------------------------------------------------
# Renderer filtering tests (Issue #38)
# ---------------------------------------------------------------------------


def _make_renderer(fmt: str = "docx", theme: str = "basic") -> MagicMock:
    r = MagicMock()
    r.format = fmt
    r.theme = theme
    return r


def _make_filter_config(
    report_formats: list[str] | None = None,
    report_theme: str = "basic",
) -> EngagementConfig:
    """Minimal EngagementConfig for filter tests."""
    return EngagementConfig(
        client_name="Test",
        tenant_id="t-1",
        auth=AuthConfig(method="device_code", tenant_id="t-1", client_id="c-1"),
        tools={},
        report_formats=report_formats or ["docx"],
        report_theme=report_theme,
    )


class TestFilterRenderers:
    def test_filters_by_format(self) -> None:
        docx = _make_renderer("docx", "basic")
        pptx = _make_renderer("pptx", "basic")
        config = _make_filter_config(report_formats=["docx"])

        result = _filter_renderers([docx, pptx], config)

        assert result == [docx]

    def test_filters_by_theme(self) -> None:
        basic = _make_renderer("docx", "basic")
        gx = _make_renderer("docx", "guardantix")
        config = _make_filter_config(report_formats=["docx"], report_theme="basic")

        result = _filter_renderers([basic, gx], config)

        assert result == [basic]

    def test_theme_agnostic_via_no_attribute(self) -> None:
        """Renderer with no theme attribute matches any config theme."""
        r = MagicMock(spec=["format", "render"])
        r.format = "docx"
        config = _make_filter_config(report_formats=["docx"], report_theme="guardantix")

        result = _filter_renderers([r], config)

        assert result == [r]

    def test_theme_agnostic_via_empty_string(self) -> None:
        """Renderer with theme='' matches any config theme."""
        r = _make_renderer("docx", "")
        config = _make_filter_config(report_formats=["docx"], report_theme="guardantix")

        result = _filter_renderers([r], config)

        assert result == [r]

    def test_combined_format_and_theme_filtering(self) -> None:
        docx_basic = _make_renderer("docx", "basic")
        docx_gx = _make_renderer("docx", "guardantix")
        pptx_basic = _make_renderer("pptx", "basic")
        config = _make_filter_config(report_formats=["docx"], report_theme="basic")

        result = _filter_renderers([docx_basic, docx_gx, pptx_basic], config)

        assert result == [docx_basic]

    def test_multiple_formats_selected(self) -> None:
        docx = _make_renderer("docx", "basic")
        pptx = _make_renderer("pptx", "basic")
        config = _make_filter_config(report_formats=["docx", "pptx"])

        result = _filter_renderers([docx, pptx], config)

        assert result == [docx, pptx]

    def test_raises_report_error_when_no_renderers_match(self) -> None:
        docx = _make_renderer("docx", "basic")
        config = _make_filter_config(report_formats=["pdf"])

        with pytest.raises(ReportError, match="No renderers match config"):
            _filter_renderers([docx], config)

    def test_raises_report_error_when_all_filtered_by_theme(self) -> None:
        gx = _make_renderer("docx", "guardantix")
        config = _make_filter_config(report_formats=["docx"], report_theme="basic")

        with pytest.raises(ReportError, match="No renderers match config"):
            _filter_renderers([gx], config)

    def test_warns_for_unmatched_format(self, caplog: pytest.LogCaptureFixture) -> None:
        docx = _make_renderer("docx", "basic")
        config = _make_filter_config(report_formats=["docx", "pptx"])

        with caplog.at_level("WARNING", logger="gxassessms.pipeline._runner"):
            result = _filter_renderers([docx], config)

        assert result == [docx]
        assert any("pptx" in record.message for record in caplog.records)

    def test_empty_renderer_list_raises_report_error(self) -> None:
        config = _make_filter_config(report_formats=["docx"])

        with pytest.raises(ReportError, match="No renderers match config"):
            _filter_renderers([], config)

    def test_logs_selection_summary(self, caplog: pytest.LogCaptureFixture) -> None:
        docx = _make_renderer("docx", "basic")
        pptx = _make_renderer("pptx", "basic")
        config = _make_filter_config(report_formats=["docx"])

        with caplog.at_level("INFO", logger="gxassessms.pipeline._runner"):
            _filter_renderers([docx, pptx], config)

        assert any("1 of 2 renderers match" in record.message for record in caplog.records)


class TestDescribeRenderers:
    def test_empty_list(self) -> None:
        assert _describe_renderers([]) == "(none discovered)"

    def test_with_theme(self) -> None:
        r = _make_renderer("docx", "basic")
        assert _describe_renderers([r]) == "format=docx,theme=basic"

    def test_without_theme(self) -> None:
        r = _make_renderer("docx", "")
        assert _describe_renderers([r]) == "format=docx"

    def test_multiple(self) -> None:
        r1 = _make_renderer("docx", "basic")
        r2 = _make_renderer("pptx", "guardantix")
        result = _describe_renderers([r1, r2])
        assert result == "format=docx,theme=basic; format=pptx,theme=guardantix"


class TestRunRenderFilterIntegration:
    def test_run_render_passes_only_filtered_renderers(
        self, harness: RunnerHarness, tmp_path: Path
    ) -> None:
        """_run_render() must filter renderers before passing to render()."""
        docx = _make_renderer("docx", "basic")
        pptx = _make_renderer("pptx", "basic")
        config = _make_filter_config(report_formats=["docx"])
        ctx = StageContext(consolidated_findings=[_make_consolidated()])

        with (
            patch(
                "gxassessms.pipeline._runner._build_report_payload",
                return_value=MagicMock(),
            ) as mock_build,
            patch("gxassessms.pipeline._runner.render") as mock_render,
        ):
            _run_render(ctx, [docx, pptx], tmp_path, config, "eng-001", harness.orchestrator)

        # render() should receive only the docx renderer, not both
        mock_render.assert_called_once_with(mock_build.return_value, [docx], tmp_path)
