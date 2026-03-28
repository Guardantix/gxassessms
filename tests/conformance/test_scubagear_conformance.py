"""ScubaGear adapter conformance tests.

Subclasses AdapterConformanceSuite with ScubaGear-specific fixtures.
All conformance assertions are inherited from the base class.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from gxassessms.adapters.scubagear import ScubaGearAdapter
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import CoverageRecord, RawToolOutput, ToolObservation
from tests.conformance.adapter_suite import AdapterConformanceSuite


class TestScubaGearConformance(AdapterConformanceSuite):
    """ScubaGear conformance tests -- all assertions inherited."""

    @pytest.fixture
    def adapter(self) -> ScubaGearAdapter:
        return ScubaGearAdapter()

    @pytest.fixture
    def fixture_dir(self) -> Path:
        return (
            Path(__file__).parent.parent.parent
            / "src"
            / "gxassessms"
            / "adapters"
            / "scubagear"
            / "fixtures"
        )

    @pytest.fixture
    def raw_tool_output(self, adapter: ScubaGearAdapter, fixture_dir: Path) -> RawToolOutput:
        """Build a RawToolOutput pointing at the ScubaGear fixture files."""
        scuba_results_path = fixture_dir / "ScubaResults.json"
        return RawToolOutput(
            tool=ToolSource.SCUBAGEAR,
            schema_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={str(scuba_results_path): "utf-8"},
            execution_metadata={"output_dir": str(fixture_dir)},
        )

    @pytest.fixture
    def normalization_rules(self) -> dict[str, Any]:
        """Load normalization rules from the YAML file."""
        rules_path = (
            Path(__file__).parent.parent.parent
            / "src"
            / "gxassessms"
            / "policy"
            / "rules"
            / "normalization.yaml"
        )
        with open(rules_path) as f:
            return yaml.safe_load(f)

    # ----- ScubaGear-specific conformance tests -----

    def test_observation_id_format(self, observations: list[ToolObservation]) -> None:
        """ScubaGear observation IDs must follow scubagear:{policy_id} format."""
        for obs in observations:
            assert obs.observation_id.startswith("scubagear:"), (
                f"ScubaGear observation_id must start with 'scubagear:': {obs.observation_id}"
            )

    def test_native_check_ids_are_scubagear_format(
        self, observations: list[ToolObservation]
    ) -> None:
        """ScubaGear check IDs follow MS.{MODULE}.{N}.{N}v{N} pattern."""
        for obs in observations:
            assert obs.native_check_id.startswith("MS."), (
                f"ScubaGear check ID must start with 'MS.': {obs.native_check_id}"
            )

    def test_multiple_severities_in_fixture(self, observations: list[ToolObservation]) -> None:
        """Fixture covers multiple criticality levels."""
        severities = {obs.native_severity for obs in observations}
        assert len(severities) >= 2

    def test_multiple_statuses_in_fixture(self, observations: list[ToolObservation]) -> None:
        """Fixture covers multiple result statuses."""
        statuses = {obs.native_status for obs in observations}
        assert len(statuses) >= 3

    def test_multiple_modules_in_fixture(self, observations: list[ToolObservation]) -> None:
        """Fixture covers multiple ScubaGear modules."""
        modules = set()
        for obs in observations:
            parts = obs.native_check_id.split(".")
            if len(parts) >= 3:
                modules.add(parts[1])
        assert len(modules) >= 3

    def test_coverage_includes_not_assessed(
        self, coverage_records: list[CoverageRecord] | None
    ) -> None:
        """Fixture includes at least one N/A check mapped to not_assessed."""
        assert coverage_records is not None
        statuses = {r.status for r in coverage_records}
        assert "not_assessed" in statuses
