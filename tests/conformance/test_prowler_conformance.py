"""Prowler adapter conformance tests.

Verifies the Prowler adapter meets all ToolAdapter Protocol requirements
using the shared AdapterConformanceSuite base class.
"""

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gxassessms.adapters.prowler import ProwlerAdapter
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import ArtifactRecord, ResolvedManifest
from tests.conformance.adapter_suite import AdapterConformanceSuite


class TestProwlerConformance(AdapterConformanceSuite):
    """Prowler-specific conformance tests."""

    @pytest.fixture
    def adapter(self) -> ProwlerAdapter:
        return ProwlerAdapter()

    @pytest.fixture
    def fixture_dir(self) -> Path:
        return (
            Path(__file__).parent.parent.parent
            / "src"
            / "gxassessms"
            / "adapters"
            / "prowler"
            / "fixtures"
        )

    @pytest.fixture
    def resolved_manifest(self, adapter: ProwlerAdapter, fixture_dir: Path) -> ResolvedManifest:
        """Build a ResolvedManifest pointing at the Prowler fixture files."""
        results_path = fixture_dir / "prowler_sample.json"
        sha = hashlib.sha256(results_path.read_bytes()).hexdigest()
        return ResolvedManifest(
            tool=ToolSource.PROWLER,
            tool_slug="prowler",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={
                str(results_path): ArtifactRecord(encoding="utf-8", sha256=sha),
            },
            execution_metadata={},
        )

    @pytest.fixture
    def normalization_rules(self) -> dict:
        """Normalization rules for Prowler."""
        return {
            "severity_map": "prowler.mappings.SEVERITY_MAP",
            "category_map": "prowler.mappings.CATEGORY_MAP",
            "dedup_key_rules": "prowler.mappings.DEDUP_KEY_RULES",
        }

    # Prowler-specific tests (flat, not nested)

    def test_status_code_fail_produces_fail_status(
        self,
        adapter: ProwlerAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        observations = adapter.parse(resolved_manifest)
        fail_obs = [
            o
            for o in observations
            if o.native_check_id == "defender_ensure_defender_for_app_services_is_on"
        ]
        assert len(fail_obs) == 1
        assert fail_obs[0].native_status == "FAIL"

    def test_status_code_pass_produces_pass_status(
        self,
        adapter: ProwlerAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        observations = adapter.parse(resolved_manifest)
        pass_obs = [
            o
            for o in observations
            if o.native_check_id == "defender_ensure_defender_for_storage_is_on"
        ]
        assert len(pass_obs) == 1
        assert pass_obs[0].native_status == "PASS"

    def test_status_code_manual_produces_manual_status(
        self,
        adapter: ProwlerAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        observations = adapter.parse(resolved_manifest)
        manual_obs = [
            o
            for o in observations
            if o.native_check_id == "storage_ensure_encryption_with_customer_managed_keys"
        ]
        assert len(manual_obs) == 1
        assert manual_obs[0].native_status == "MANUAL"

    def test_observation_ids_are_prefixed(
        self,
        adapter: ProwlerAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        observations = adapter.parse(resolved_manifest)
        for obs in observations:
            assert obs.observation_id.startswith("prowler:")

    def test_check_id_from_metadata_event_code(
        self,
        adapter: ProwlerAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        """Verify check IDs come from metadata.event_code, not finding_info.uid."""
        observations = adapter.parse(resolved_manifest)
        for obs in observations:
            # Check IDs should be clean snake_case, not have prowler-azure- prefix
            assert "prowler-azure-" not in obs.native_check_id
            assert "_" in obs.native_check_id  # All Prowler check IDs contain underscores

    def test_benchmark_refs_populated(
        self,
        adapter: ProwlerAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        """Verify compliance data extracted from unmapped.compliance."""
        observations = adapter.parse(resolved_manifest)
        first = observations[0]
        assert len(first.benchmark_refs) > 0
        assert any("CIS-2.1" in ref for ref in first.benchmark_refs)

    def test_validate_raw_rejects_non_list(
        self,
        adapter: ProwlerAdapter,
        tmp_path: Path,
    ) -> None:
        bad_file = tmp_path / "bad.ocsf.json"
        bad_file.write_text('{"not": "an array"}')
        sha = hashlib.sha256(bad_file.read_bytes()).hexdigest()
        raw = ResolvedManifest(
            tool=ToolSource.PROWLER,
            tool_slug="prowler",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={str(bad_file): ArtifactRecord(encoding="utf-8", sha256=sha)},
            execution_metadata={},
        )
        from gxassessms.core.contracts.errors import RawOutputValidationError

        with pytest.raises(RawOutputValidationError, match="Expected JSON array"):
            adapter.validate_raw(raw)

    def test_validate_raw_rejects_missing_fields(
        self,
        adapter: ProwlerAdapter,
        tmp_path: Path,
    ) -> None:
        bad_file = tmp_path / "bad.ocsf.json"
        bad_file.write_text('[{"noFindingInfo": true}]')
        sha = hashlib.sha256(bad_file.read_bytes()).hexdigest()
        raw = ResolvedManifest(
            tool=ToolSource.PROWLER,
            tool_slug="prowler",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={str(bad_file): ArtifactRecord(encoding="utf-8", sha256=sha)},
            execution_metadata={},
        )
        from gxassessms.core.contracts.errors import RawOutputValidationError

        with pytest.raises(RawOutputValidationError, match="missing 'finding_info'"):
            adapter.validate_raw(raw)

    def test_validate_raw_rejects_missing_metadata(
        self,
        adapter: ProwlerAdapter,
        tmp_path: Path,
    ) -> None:
        bad_file = tmp_path / "bad.ocsf.json"
        bad_file.write_text('[{"finding_info": {"uid": "x"}, "status_code": "PASS"}]')
        sha = hashlib.sha256(bad_file.read_bytes()).hexdigest()
        raw = ResolvedManifest(
            tool=ToolSource.PROWLER,
            tool_slug="prowler",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={str(bad_file): ArtifactRecord(encoding="utf-8", sha256=sha)},
            execution_metadata={},
        )
        from gxassessms.core.contracts.errors import RawOutputValidationError

        with pytest.raises(RawOutputValidationError, match=r"missing 'metadata\.event_code'"):
            adapter.validate_raw(raw)

    def test_validate_raw_rejects_metadata_without_event_code(
        self,
        adapter: ProwlerAdapter,
        tmp_path: Path,
    ) -> None:
        """metadata present but event_code missing should fail validation."""
        bad_file = tmp_path / "bad.ocsf.json"
        bad_file.write_text(
            '[{"finding_info": {"uid": "x"}, "status_code": "PASS", '
            '"metadata": {"version": "1.4.0"}}]'
        )
        sha = hashlib.sha256(bad_file.read_bytes()).hexdigest()
        raw = ResolvedManifest(
            tool=ToolSource.PROWLER,
            tool_slug="prowler",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={str(bad_file): ArtifactRecord(encoding="utf-8", sha256=sha)},
            execution_metadata={},
        )
        from gxassessms.core.contracts.errors import RawOutputValidationError

        with pytest.raises(RawOutputValidationError, match=r"missing 'metadata\.event_code'"):
            adapter.validate_raw(raw)
