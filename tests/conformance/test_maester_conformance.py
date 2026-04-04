"""Maester adapter conformance tests.

Subclasses AdapterConformanceSuite with Maester-specific fixtures.
All conformance assertions are inherited from the base class.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from gxassessms.adapters.maester import MaesterAdapter
from gxassessms.core.domain.enums import CoverageStatus, ToolSource
from gxassessms.core.domain.models import (
    ArtifactRecord,
    CoverageRecord,
    ResolvedManifest,
    ToolObservation,
)
from tests.conformance.adapter_suite import AdapterConformanceSuite


class TestMaesterConformance(AdapterConformanceSuite):
    """Maester conformance tests -- all assertions inherited from AdapterConformanceSuite."""

    @pytest.fixture
    def adapter(self) -> MaesterAdapter:
        return MaesterAdapter()

    @pytest.fixture
    def fixture_dir(self) -> Path:
        return (
            Path(__file__).parent.parent.parent
            / "src"
            / "gxassessms"
            / "adapters"
            / "maester"
            / "fixtures"
        )

    @pytest.fixture
    def resolved_manifest(self, adapter: MaesterAdapter, fixture_dir: Path) -> ResolvedManifest:
        """Build a ResolvedManifest pointing at the Maester fixture files."""
        results_path = fixture_dir / "MaesterTestResults.json"
        sha = hashlib.sha256(results_path.read_bytes()).hexdigest()
        return ResolvedManifest(
            tool=ToolSource.MAESTER,
            tool_slug="maester",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={
                str(results_path): ArtifactRecord(encoding="utf-8", sha256=sha),
            },
            execution_metadata={},
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

    # Inherited fixtures: observations, normalized_findings, coverage_records
    # Inherited tests: all test_* methods from AdapterConformanceSuite

    # ----- Maester-specific conformance tests (flat, not nested) -----

    def test_observation_id_format(self, observations: list[ToolObservation]) -> None:
        """Maester observation IDs must follow maester:{test_id} format."""
        for obs in observations:
            assert obs.observation_id.startswith("maester:"), (
                f"Maester observation_id must start with 'maester:': {obs.observation_id}"
            )

    def test_native_check_ids_use_known_prefixes(self, observations: list[ToolObservation]) -> None:
        """Maester check IDs use multiple framework prefixes."""
        valid_prefixes = ("CIS.M365.", "CISA.MS.", "EIDSCA.", "MT.", "ORCA.")
        for obs in observations:
            assert any(obs.native_check_id.startswith(p) for p in valid_prefixes), (
                f"Maester check ID must start with a known prefix: {obs.native_check_id}"
            )

    def test_multiple_id_formats_in_fixture(self, observations: list[ToolObservation]) -> None:
        """Fixture covers multiple Maester ID formats."""
        prefixes_seen = set()
        for obs in observations:
            for prefix in ("CIS.M365.", "CISA.MS.", "EIDSCA.", "MT.", "ORCA."):
                if obs.native_check_id.startswith(prefix):
                    prefixes_seen.add(prefix)
        assert len(prefixes_seen) >= 4, (
            f"Fixture should cover at least 4 ID format prefixes, found: {prefixes_seen}"
        )

    def test_multiple_severities_in_fixture(self, observations: list[ToolObservation]) -> None:
        """Fixture covers multiple severity levels."""
        severities = {obs.native_severity for obs in observations}
        assert len(severities) >= 4, (
            f"Fixture should cover at least 4 severity levels, found: {severities}"
        )

    def test_all_five_statuses_in_fixture(self, observations: list[ToolObservation]) -> None:
        """Fixture covers all 5 Maester result statuses."""
        statuses = {obs.native_status for obs in observations}
        expected = {"Passed", "Failed", "Skipped", "Error", "NotRun"}
        assert statuses == expected, f"Fixture should cover all 5 statuses, found: {statuses}"

    def test_multiple_blocks_in_fixture(self, observations: list[ToolObservation]) -> None:
        """Fixture covers multiple Maester Block values (framework areas)."""
        blocks = set()
        for obs in observations:
            block = obs.raw_data.get("Block", "")
            if block:
                blocks.add(block)
        assert len(blocks) >= 4, f"Fixture should cover at least 4 Block values, found: {blocks}"

    def test_coverage_includes_not_assessed(
        self,
        coverage_records: list[CoverageRecord] | None,
    ) -> None:
        """Fixture includes Skipped/Error/NotRun checks mapped to not_assessed."""
        assert coverage_records is not None
        statuses = {r.status for r in coverage_records}
        assert CoverageStatus.NOT_ASSESSED in statuses, (
            "Fixture should include at least one not_assessed coverage record"
        )
        not_assessed = [r for r in coverage_records if r.status == CoverageStatus.NOT_ASSESSED]
        assert len(not_assessed) >= 3, (
            "Fixture should have at least 3 not_assessed records (Skipped + Error + NotRun)"
        )
