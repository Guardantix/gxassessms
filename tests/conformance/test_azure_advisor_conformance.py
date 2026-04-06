"""Azure Advisor adapter conformance tests.

Verifies the Azure Advisor adapter meets all ToolAdapter Protocol requirements
using the shared AdapterConformanceSuite base class.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from gxassessms.adapters.azure_advisor import AzureAdvisorAdapter
from gxassessms.core.contracts.errors import RawOutputValidationError
from gxassessms.core.domain.enums import FindingStatus, ToolSource
from gxassessms.core.domain.models import ArtifactRecord, ResolvedManifest
from gxassessms.core.hashing import sha256_file
from tests.conformance.adapter_suite import AdapterConformanceSuite


def _make_manifest(file_path: Path) -> ResolvedManifest:
    """Build a ResolvedManifest from a single JSON file."""
    sha = sha256_file(file_path)
    return ResolvedManifest(
        tool=ToolSource.AZURE_ADVISOR,
        tool_slug="azure-advisor",
        schema_version="1.0.0",
        manifest_version="1.0.0",
        timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
        file_manifest={str(file_path): ArtifactRecord(encoding="utf-8", sha256=sha)},
        execution_metadata={},
    )


class TestAzureAdvisorConformance(AdapterConformanceSuite):
    """Azure Advisor-specific conformance tests."""

    @pytest.fixture
    def adapter(self) -> AzureAdvisorAdapter:
        return AzureAdvisorAdapter()

    @pytest.fixture
    def fixture_dir(self) -> Path:
        return (
            Path(__file__).parent.parent.parent
            / "src"
            / "gxassessms"
            / "adapters"
            / "azure_advisor"
            / "fixtures"
        )

    @pytest.fixture
    def resolved_manifest(
        self, adapter: AzureAdvisorAdapter, fixture_dir: Path
    ) -> ResolvedManifest:
        return _make_manifest(fixture_dir / "azure_advisor_sample.json")

    @pytest.fixture
    def normalization_rules(self) -> dict:
        """Normalization rules for Azure Advisor."""
        return {
            "severity_map": "azure_advisor.mappings.IMPACT_TO_SEVERITY_MAP",
            "category_map": "azure_advisor.mappings.CATEGORY_MAP",
            "dedup_key_rules": "azure_advisor.mappings.DEDUP_KEY_RULES",
        }

    def test_all_observations_are_fail_status(
        self,
        adapter: AzureAdvisorAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        """Azure Advisor only returns active recommendations -- all FAIL."""
        observations = adapter.parse(resolved_manifest)
        for obs in observations:
            assert obs.native_status == FindingStatus.FAIL

    def test_observation_ids_are_prefixed(
        self,
        adapter: AzureAdvisorAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        observations = adapter.parse(resolved_manifest)
        for obs in observations:
            assert obs.observation_id.startswith("azure_advisor:")

    def test_native_check_id_is_recommendation_type_id(
        self,
        adapter: AzureAdvisorAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        """native_check_id should be recommendationTypeId, not name."""
        observations = adapter.parse(resolved_manifest)
        first = observations[0]
        # recommendationTypeId from fixture
        assert first.native_check_id == ("242639fd-cd73-4be2-8f55-70478db8d1a5")
        # NOT the name (per-instance GUID)
        assert first.native_check_id != ("b7762bb1-933d-32af-983e-74455d2943ae")

    def test_validate_raw_accepts_empty_value_array(
        self,
        adapter: AzureAdvisorAdapter,
        tmp_path: Path,
    ) -> None:
        """Empty value array is valid -- no recommendations."""
        empty_file = tmp_path / "empty.json"
        empty_file.write_text('{"value": []}')
        raw = _make_manifest(empty_file)
        adapter.validate_raw(raw)

    def test_parse_empty_value_returns_zero_observations(
        self,
        adapter: AzureAdvisorAdapter,
        tmp_path: Path,
    ) -> None:
        """Empty value array produces zero observations, not an error."""
        empty_file = tmp_path / "empty.json"
        empty_file.write_text('{"value": []}')
        raw = _make_manifest(empty_file)
        observations = adapter.parse(raw)
        assert observations == []

    def test_validate_raw_rejects_missing_value_key(
        self,
        adapter: AzureAdvisorAdapter,
        tmp_path: Path,
    ) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text('{"recommendations": []}')
        raw = _make_manifest(bad_file)

        with pytest.raises(
            RawOutputValidationError,
            match="Missing 'value'",
        ):
            adapter.validate_raw(raw)

    def test_validate_raw_rejects_non_dict(
        self,
        adapter: AzureAdvisorAdapter,
        tmp_path: Path,
    ) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text('[{"not": "an envelope"}]')
        raw = _make_manifest(bad_file)

        with pytest.raises(
            RawOutputValidationError,
            match="Expected JSON object",
        ):
            adapter.validate_raw(raw)

    def test_null_risk_handled(
        self,
        adapter: AzureAdvisorAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        """Recommendations with null risk parse without error."""
        observations = adapter.parse(resolved_manifest)
        # First fixture recommendation has risk=null
        first = observations[0]
        assert first.raw_data["risk"] is None

    def test_multiple_categories_represented(
        self,
        adapter: AzureAdvisorAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        """Fixture should cover multiple Advisor categories."""
        observations = adapter.parse(resolved_manifest)
        categories = {obs.raw_data["category"] for obs in observations}
        assert len(categories) >= 3, f"Expected at least 3 categories, got {categories}"
