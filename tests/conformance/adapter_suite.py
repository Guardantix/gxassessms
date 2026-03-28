"""AdapterConformanceSuite -- reusable base class for adapter conformance tests.

Every adapter test plan subclasses this and overrides the three required fixtures
(adapter, raw_tool_output, normalization_rules). All conformance assertions are
inherited -- subclasses add nothing beyond fixture wiring.

Design notes:
- All test methods are flat on the class. Nested classes break pytest fixture
  inheritance for subclasses.
- Normalization short-circuits to INFO for PASS/N/A observations by design; tests
  assert only that severity is a valid Severity instance, not a specific value.
- CoverageStatus is a StrEnum: "assessed", "partially_assessed", "not_assessed".
"""

from __future__ import annotations

from typing import Any

import pytest

from gxassessms.core.domain.enums import Category, FindingStatus, Severity
from gxassessms.core.domain.models import CoverageRecord, Finding, RawToolOutput, ToolObservation


class AdapterConformanceSuite:
    """Base conformance suite.  Subclasses override the three required fixtures."""

    # ------------------------------------------------------------------
    # Required fixtures -- subclasses MUST override
    # ------------------------------------------------------------------

    @pytest.fixture
    def adapter(self) -> Any:
        raise NotImplementedError("Subclass must provide adapter fixture")

    @pytest.fixture
    def raw_tool_output(self, adapter: Any) -> RawToolOutput:
        raise NotImplementedError("Subclass must provide raw_tool_output fixture")

    @pytest.fixture
    def normalization_rules(self) -> dict:
        raise NotImplementedError("Subclass must provide normalization_rules fixture")

    # ------------------------------------------------------------------
    # Derived fixtures -- computed from required fixtures
    # ------------------------------------------------------------------

    @pytest.fixture
    def observations(self, adapter: Any, raw_tool_output: RawToolOutput) -> list[ToolObservation]:
        """Parse raw tool output into ToolObservations."""
        return adapter.parse(raw_tool_output)

    @pytest.fixture
    def normalized_findings(
        self,
        observations: list[ToolObservation],
        adapter: Any,
        normalization_rules: dict,
    ) -> list[Finding]:
        """Normalize observations into Findings using DefaultNormalizationPolicy."""
        from gxassessms.policy.normalization import DefaultNormalizationPolicy

        policy = DefaultNormalizationPolicy(rules=normalization_rules)

        adapter_severity_map: dict[tuple[str, str], str] = {}
        adapter_category_map: dict[str, str] = {}
        adapter_dedup_keys: dict[str, str] = {}

        if hasattr(adapter, "severity_map"):
            # Severity enum values are StrEnum -- .value gives "CRITICAL" etc.
            adapter_severity_map = {
                k: v.value if hasattr(v, "value") else v for k, v in adapter.severity_map.items()
            }
        if hasattr(adapter, "category_map"):
            # Category enum .name gives "IDENTITY_ACCESS"; policy handles both name and value.
            adapter_category_map = {
                k: v.name if hasattr(v, "name") else v for k, v in adapter.category_map.items()
            }
        if hasattr(adapter, "dedup_key_rules"):
            adapter_dedup_keys = adapter.dedup_key_rules

        return policy.normalize(
            observations=observations,
            adapter_severity_map=adapter_severity_map,
            adapter_category_map=adapter_category_map,
            adapter_dedup_keys=adapter_dedup_keys,
        )

    @pytest.fixture
    def coverage_records(
        self, adapter: Any, raw_tool_output: RawToolOutput
    ) -> list[CoverageRecord] | None:
        """Call adapter.coverage() if coverage_export capability is present, else None."""
        if "coverage_export" in getattr(adapter, "capabilities", frozenset()):
            return adapter.coverage(raw_tool_output)
        return None

    # ------------------------------------------------------------------
    # Parser conformance
    # ------------------------------------------------------------------

    def test_parser_returns_nonempty_list(self, observations: list[ToolObservation]) -> None:
        assert len(observations) > 0, "adapter.parse() returned an empty list"

    def test_all_observations_are_tool_observations(
        self, observations: list[ToolObservation]
    ) -> None:
        for obs in observations:
            assert isinstance(obs, ToolObservation), (
                f"Expected ToolObservation, got {type(obs).__name__}"
            )

    def test_every_observation_has_nonempty_id(self, observations: list[ToolObservation]) -> None:
        for obs in observations:
            assert obs.observation_id, f"observation_id is empty for observation: {obs!r}"

    def test_every_observation_has_nonempty_title(
        self, observations: list[ToolObservation]
    ) -> None:
        for obs in observations:
            assert obs.title, f"title is empty for observation_id={obs.observation_id!r}"

    def test_every_observation_has_native_severity(
        self, observations: list[ToolObservation]
    ) -> None:
        for obs in observations:
            assert obs.native_severity, (
                f"native_severity is empty for observation_id={obs.observation_id!r}"
            )

    def test_every_observation_has_native_status(self, observations: list[ToolObservation]) -> None:
        for obs in observations:
            assert obs.native_status, (
                f"native_status is empty for observation_id={obs.observation_id!r}"
            )

    def test_every_observation_tool_matches_adapter(
        self, observations: list[ToolObservation], adapter: Any
    ) -> None:
        expected = adapter.tool_name
        for obs in observations:
            assert obs.tool.value == expected, (
                f"observation tool {obs.tool.value!r} != adapter tool_name {expected!r}"
            )

    # ------------------------------------------------------------------
    # Normalization conformance
    # ------------------------------------------------------------------

    def test_normalized_findings_nonempty(self, normalized_findings: list[Finding]) -> None:
        assert len(normalized_findings) > 0, "normalization produced no findings"

    def test_every_finding_has_dedup_key(self, normalized_findings: list[Finding]) -> None:
        for f in normalized_findings:
            assert f.dedup_keys, f"dedup_keys is empty for finding_key={f.finding_key!r}"

    def test_all_severities_are_valid(self, normalized_findings: list[Finding]) -> None:
        for f in normalized_findings:
            assert isinstance(f.severity, Severity), (
                f"severity {f.severity!r} is not a Severity enum instance "
                f"(finding_key={f.finding_key!r})"
            )

    def test_all_statuses_are_valid(self, normalized_findings: list[Finding]) -> None:
        for f in normalized_findings:
            assert isinstance(f.status, FindingStatus), (
                f"status {f.status!r} is not a FindingStatus enum instance "
                f"(finding_key={f.finding_key!r})"
            )

    def test_all_categories_are_valid(self, normalized_findings: list[Finding]) -> None:
        for f in normalized_findings:
            assert isinstance(f.category, Category), (
                f"category {f.category!r} is not a Category enum instance "
                f"(finding_key={f.finding_key!r})"
            )

    # ------------------------------------------------------------------
    # Serialization conformance
    # ------------------------------------------------------------------

    def test_observations_round_trip(self, observations: list[ToolObservation]) -> None:
        for obs in observations:
            json_str = obs.model_dump_json()
            restored = ToolObservation.model_validate_json(json_str)
            assert restored.observation_id == obs.observation_id
            assert restored.tool == obs.tool
            assert restored.native_check_id == obs.native_check_id
            assert restored.title == obs.title

    def test_findings_round_trip(self, normalized_findings: list[Finding]) -> None:
        for f in normalized_findings:
            json_str = f.model_dump_json()
            restored = Finding.model_validate_json(json_str)
            assert restored.finding_key == f.finding_key
            assert restored.tool == f.tool
            assert restored.severity == f.severity
            assert restored.status == f.status
            assert restored.category == f.category

    # ------------------------------------------------------------------
    # Capability conformance
    # ------------------------------------------------------------------

    def test_collect_capability_implies_method(self, adapter: Any) -> None:
        if "collect" in getattr(adapter, "capabilities", frozenset()):
            assert hasattr(adapter, "collect"), (
                "Adapter declares 'collect' capability but has no collect() method"
            )

    def test_parse_capability_implies_method(self, adapter: Any) -> None:
        if "parse" in getattr(adapter, "capabilities", frozenset()):
            assert hasattr(adapter, "parse"), (
                "Adapter declares 'parse' capability but has no parse() method"
            )

    def test_prerequisites_capability_implies_method(self, adapter: Any) -> None:
        if "prerequisites" in getattr(adapter, "capabilities", frozenset()):
            assert hasattr(adapter, "check_prerequisites"), (
                "Adapter declares 'prerequisites' capability but has no "
                "check_prerequisites() method"
            )

    def test_coverage_export_capability_implies_method(self, adapter: Any) -> None:
        if "coverage_export" in getattr(adapter, "capabilities", frozenset()):
            assert hasattr(adapter, "coverage"), (
                "Adapter declares 'coverage_export' capability but has no coverage() method"
            )

    def test_benchmark_mapping_capability_implies_property(self, adapter: Any) -> None:
        if "benchmark_mapping" in getattr(adapter, "capabilities", frozenset()):
            assert hasattr(adapter, "dedup_key_rules"), (
                "Adapter declares 'benchmark_mapping' capability but has no "
                "dedup_key_rules property"
            )

    # ------------------------------------------------------------------
    # Coverage conformance
    # ------------------------------------------------------------------

    def test_coverage_records_nonempty(self, coverage_records: list[CoverageRecord] | None) -> None:
        if coverage_records is None:
            pytest.skip("Adapter does not expose coverage_export capability")
        assert len(coverage_records) > 0, "adapter.coverage() returned an empty list"

    def test_coverage_records_have_valid_tool(
        self, adapter: Any, coverage_records: list[CoverageRecord] | None
    ) -> None:
        if coverage_records is None:
            pytest.skip("Adapter does not expose coverage_export capability")
        expected = adapter.tool_name
        for rec in coverage_records:
            assert rec.tool.value == expected, (
                f"coverage record tool {rec.tool.value!r} != adapter tool_name {expected!r}"
            )

    def test_coverage_records_have_valid_status(
        self, coverage_records: list[CoverageRecord] | None
    ) -> None:
        if coverage_records is None:
            pytest.skip("Adapter does not expose coverage_export capability")
        valid = {"assessed", "partially_assessed", "not_assessed"}
        for rec in coverage_records:
            assert rec.status in valid, (
                f"coverage record status {rec.status!r} is not one of {valid}"
            )
