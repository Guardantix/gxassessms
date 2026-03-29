"""Tests for pipeline stage functions.

Each stage function is tested in isolation with mock collaborators.
Stage functions are pure where possible (collect is the exception).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from gxassessms.core.config.config import (
    AuthConfig,
    EngagementConfig,
    ToolConfig,
)
from gxassessms.core.contracts.types import (
    AdapterRunStatus,
    QAResult,
)
from gxassessms.core.domain.enums import (
    Category,
    FindingStatus,
    Severity,
    ToolSource,
)
from gxassessms.core.domain.models import (
    AdapterResult,
    ConfidenceScore,
    ConsolidatedFinding,
    Finding,
    RawToolOutput,
    ReportPayload,
    SourceEvidence,
    ToolObservation,
)
from gxassessms.pipeline.stages import (
    Stage,
    collect,
    consolidate,
    normalize,
    parse,
    qa_review,
    render,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_config(**overrides: Any) -> EngagementConfig:
    defaults: dict[str, Any] = {
        "client_name": "Test",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "auth": AuthConfig(
            method="client_credential",
            tenant_id="00000000-0000-0000-0000-000000000001",
            client_id="00000000-0000-0000-0000-000000000002",
            client_secret_env="GX_SECRET",  # pragma: allowlist secret
        ),
        "tools": {"scubagear": ToolConfig(enabled=True)},
        "max_parallel": 2,
    }
    defaults.update(overrides)
    return EngagementConfig(**defaults)


def _make_raw_output(tool: ToolSource = ToolSource.SCUBAGEAR) -> RawToolOutput:
    return RawToolOutput(
        tool=tool,
        schema_version="1.0.0",
        timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
        file_manifest={"TestResults.json": "utf-8"},
        execution_metadata={"exit_code": 0},
    )


def _make_adapter_result(
    name: str = "ScubaGear",
    status: str = "SUCCESS",
    raw_output: RawToolOutput | None = None,
) -> AdapterResult:
    return AdapterResult(
        adapter_name=name,
        status=status,
        raw_output=raw_output or _make_raw_output(),
        error=None,
        duration_seconds=120.5,
    )


def _make_observation(
    check_id: str = "MS.AAD.3.1v1",
    tool: ToolSource = ToolSource.SCUBAGEAR,
) -> ToolObservation:
    return ToolObservation(
        observation_id=f"{tool.value.lower()}:{check_id}",
        tool=tool,
        native_check_id=check_id,
        title=f"Check {check_id}",
        native_severity="Shall",
        native_status="Fail",
        description=f"Description for {check_id}",
        benchmark_refs=["CIS M365 1.1.1"],
    )


def _make_finding(
    key: str = "cis:m365:1.1.1",
    tool: ToolSource = ToolSource.SCUBAGEAR,
    severity: Severity = Severity.CRITICAL,
) -> Finding:
    return Finding(
        observation_id=f"{tool.value.lower()}:{uuid.uuid4().hex[:8]}",
        native_check_id="MS.AAD.3.1v1",
        finding_key=key,
        tool=tool,
        title=f"Finding {key}",
        severity=severity,
        status=FindingStatus.FAIL,
        category=Category.IDENTITY_ACCESS,
        description=f"Test finding from {tool.value}",
        dedup_keys=[key],
        benchmark_refs=["CIS M365 1.1.1"],
    )


def _make_consolidated(
    key: str = "cis:m365:1.1.1",
) -> ConsolidatedFinding:
    return ConsolidatedFinding(
        finding_instance_id=str(uuid.uuid4()),
        finding_key=key,
        title=f"Consolidated {key}",
        severity=Severity.CRITICAL,
        status=FindingStatus.FAIL,
        category=Category.IDENTITY_ACCESS,
        description="Consolidated test finding",
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
    )


def _make_mock_adapter(
    name: str = "ScubaGear",
    tool_source: ToolSource = ToolSource.SCUBAGEAR,
) -> MagicMock:
    adapter = MagicMock()
    adapter.tool_name = name
    adapter.capabilities = frozenset({"collect", "parse"})
    adapter.collect.return_value = _make_raw_output(tool_source)
    adapter.validate_raw.return_value = None
    adapter.parse.return_value = [_make_observation()]
    adapter.coverage.return_value = []
    adapter.authenticate.return_value = None
    return adapter


# ---------------------------------------------------------------------------
# Stage enum tests
# ---------------------------------------------------------------------------


class TestStageEnum:
    def test_all_stages_exist(self) -> None:
        expected = {
            "COLLECT",
            "PARSE",
            "NORMALIZE",
            "CONSOLIDATE",
            "QA_REVIEW",
            "RENDER",
        }
        assert {s.value for s in Stage} == expected

    def test_is_str_enum(self) -> None:
        assert isinstance(Stage.COLLECT, str)
        assert Stage.COLLECT == "COLLECT"

    def test_stage_ordering(self) -> None:
        ordered = [
            Stage.COLLECT,
            Stage.PARSE,
            Stage.NORMALIZE,
            Stage.CONSOLIDATE,
            Stage.QA_REVIEW,
            Stage.RENDER,
        ]
        assert list(Stage) == ordered


# ---------------------------------------------------------------------------
# collect() tests
# ---------------------------------------------------------------------------


class TestCollectStage:
    def test_single_adapter_success(self) -> None:
        config = _make_config()
        adapter = _make_mock_adapter()
        results = collect(config, [adapter])
        assert len(results) == 1
        assert results[0].status == AdapterRunStatus.SUCCESS.value
        assert results[0].adapter_name == "ScubaGear"
        assert results[0].raw_output is not None

    def test_parallel_execution_multiple_adapters(self) -> None:
        config = _make_config(max_parallel=3)
        adapters = [
            _make_mock_adapter("ScubaGear", ToolSource.SCUBAGEAR),
            _make_mock_adapter("Maester", ToolSource.MAESTER),
        ]
        results = collect(config, adapters)
        assert len(results) == 2
        names = {r.adapter_name for r in results}
        assert names == {"ScubaGear", "Maester"}

    def test_adapter_failure_captured_not_raised(self) -> None:
        config = _make_config()
        adapter = _make_mock_adapter()
        adapter.collect.side_effect = RuntimeError("PowerShell crashed")
        results = collect(config, [adapter])
        assert len(results) == 1
        assert results[0].status == AdapterRunStatus.FAILED.value
        assert results[0].raw_output is None
        assert "PowerShell crashed" in results[0].error

    def test_adapter_timeout_captured(self) -> None:
        config = _make_config()
        adapter = _make_mock_adapter()
        adapter.collect.side_effect = TimeoutError("Adapter timed out")
        results = collect(config, [adapter])
        assert len(results) == 1
        assert results[0].status == AdapterRunStatus.TIMEOUT.value

    def test_empty_adapters_returns_empty(self) -> None:
        config = _make_config()
        results = collect(config, [])
        assert results == []

    def test_mixed_success_and_failure(self) -> None:
        config = _make_config()
        good_adapter = _make_mock_adapter("ScubaGear")
        bad_adapter = _make_mock_adapter("Maester")
        bad_adapter.collect.side_effect = RuntimeError("Crash")
        results = collect(config, [good_adapter, bad_adapter])
        assert len(results) == 2
        statuses = {r.adapter_name: r.status for r in results}
        assert statuses["ScubaGear"] == AdapterRunStatus.SUCCESS.value
        assert statuses["Maester"] == AdapterRunStatus.FAILED.value


# ---------------------------------------------------------------------------
# parse() tests
# ---------------------------------------------------------------------------


class TestParseStage:
    def test_parse_successful_results(self) -> None:
        adapter = _make_mock_adapter()
        result = _make_adapter_result()
        observations = parse([result], [adapter])
        assert len(observations) == 1
        adapter.parse.assert_called_once_with(result.raw_output)

    def test_skips_failed_adapters(self) -> None:
        adapter = _make_mock_adapter()
        failed_result = AdapterResult(
            adapter_name="ScubaGear",
            status=AdapterRunStatus.FAILED.value,
            raw_output=None,
            error="PowerShell crashed",
            duration_seconds=5.0,
        )
        observations = parse([failed_result], [adapter])
        assert observations == []
        adapter.parse.assert_not_called()

    def test_skips_timed_out_adapters(self) -> None:
        adapter = _make_mock_adapter()
        timeout_result = AdapterResult(
            adapter_name="ScubaGear",
            status=AdapterRunStatus.TIMEOUT.value,
            raw_output=None,
            error="Timeout",
            duration_seconds=600.0,
        )
        observations = parse([timeout_result], [adapter])
        assert observations == []

    def test_validates_raw_before_parsing(self) -> None:
        adapter = _make_mock_adapter()
        result = _make_adapter_result()
        parse([result], [adapter])
        adapter.validate_raw.assert_called_once_with(result.raw_output)

    def test_multiple_adapters_concatenated(self) -> None:
        adapter1 = _make_mock_adapter("ScubaGear")
        adapter1.parse.return_value = [
            _make_observation("MS.AAD.3.1v1"),
            _make_observation("MS.AAD.3.2v1"),
        ]
        adapter2 = _make_mock_adapter("Maester")
        adapter2.parse.return_value = [_make_observation("MT.1001")]
        result1 = _make_adapter_result("ScubaGear")
        result2 = _make_adapter_result("Maester")
        observations = parse([result1, result2], [adapter1, adapter2])
        assert len(observations) == 3

    def test_empty_results_returns_empty(self) -> None:
        observations = parse([], [])
        assert observations == []


# ---------------------------------------------------------------------------
# normalize() tests
# ---------------------------------------------------------------------------


class TestNormalizeStage:
    def test_delegates_to_policy(self) -> None:
        observations = [_make_observation()]
        policy = MagicMock()
        expected_findings = [_make_finding()]
        policy.normalize.return_value = expected_findings
        severity_map = {"ScubaGear": {"MS.AAD.3.1v1": "HIGH"}}
        category_map = {"ScubaGear": {"MS.AAD.3.1v1": "IDENTITY_ACCESS"}}
        dedup_keys = {"ScubaGear": ["finding_key"]}
        results = normalize(
            observations,
            policy,
            adapter_severity_map=severity_map,
            adapter_category_map=category_map,
            adapter_dedup_keys=dedup_keys,
        )
        assert results == expected_findings
        policy.normalize.assert_called_once_with(
            observations=observations,
            adapter_severity_map=severity_map,
            adapter_category_map=category_map,
            adapter_dedup_keys=dedup_keys,
        )

    def test_empty_observations_returns_empty(self) -> None:
        policy = MagicMock()
        policy.normalize.return_value = []
        results = normalize([], policy)
        assert results == []

    def test_none_maps_default_to_empty_dicts(self) -> None:
        observations = [_make_observation()]
        policy = MagicMock()
        policy.normalize.return_value = []
        normalize(observations, policy)
        policy.normalize.assert_called_once_with(
            observations=observations,
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )


# ---------------------------------------------------------------------------
# consolidate() tests
# ---------------------------------------------------------------------------


class TestConsolidateStage:
    def test_delegates_to_rule(self) -> None:
        findings = [_make_finding(), _make_finding()]
        rule = MagicMock()
        expected = [_make_consolidated()]
        rule.consolidate.return_value = expected
        results = consolidate(findings, rule)
        assert results == expected
        rule.consolidate.assert_called_once_with(findings)

    def test_empty_findings_returns_empty(self) -> None:
        rule = MagicMock()
        rule.consolidate.return_value = []
        results = consolidate([], rule)
        assert results == []


# ---------------------------------------------------------------------------
# qa_review() tests
# ---------------------------------------------------------------------------


class TestQAReviewStage:
    def test_delegates_to_strategy(self) -> None:
        findings = [_make_consolidated()]
        strategy = MagicMock()
        expected_results: list[QAResult] = []
        strategy.review_findings.return_value = expected_results
        result = qa_review(findings, strategy)
        assert result == expected_results
        strategy.review_findings.assert_called_once_with(findings)

    def test_empty_findings(self) -> None:
        strategy = MagicMock()
        strategy.review_findings.return_value = []
        result = qa_review([], strategy)
        assert result == []


# ---------------------------------------------------------------------------
# render() tests
# ---------------------------------------------------------------------------


class TestRenderStage:
    def test_delegates_to_renderers(self, tmp_path: Path) -> None:
        payload = ReportPayload(
            engagement_id="eng-001",
            tenant_name="Test",
            assessment_date="2026-03-25",
            tool_sources=["ScubaGear"],
            findings=[],
            coverage=[],
            narratives={"executive_summary": "", "roadmap": ""},
            metadata={},
        )
        renderer = MagicMock()
        output_file = tmp_path / "report.docx"
        renderer.render.return_value = output_file
        paths = render(payload, [renderer], tmp_path)
        assert len(paths) == 1
        assert paths[0] == output_file
        renderer.render.assert_called_once_with(payload, tmp_path)

    def test_multiple_renderers(self, tmp_path: Path) -> None:
        payload = ReportPayload(
            engagement_id="eng-001",
            tenant_name="Test",
            assessment_date="2026-03-25",
            tool_sources=["ScubaGear"],
            findings=[],
            coverage=[],
            narratives={"executive_summary": "", "roadmap": ""},
            metadata={},
        )
        r1 = MagicMock()
        r1.render.return_value = tmp_path / "report.docx"
        r2 = MagicMock()
        r2.render.return_value = tmp_path / "report.pptx"
        paths = render(payload, [r1, r2], tmp_path)
        assert len(paths) == 2

    def test_empty_renderers_returns_empty(self, tmp_path: Path) -> None:
        payload = ReportPayload(
            engagement_id="eng-001",
            tenant_name="Test",
            assessment_date="2026-03-25",
            tool_sources=[],
            findings=[],
            coverage=[],
            narratives={},
            metadata={},
        )
        paths = render(payload, [], tmp_path)
        assert paths == []
