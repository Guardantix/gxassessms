"""Secure Score adapter conformance tests.

Verifies the Secure Score adapter meets all ToolAdapter Protocol requirements
using the shared AdapterConformanceSuite base class.
"""

from __future__ import annotations

import hashlib
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from gxassessms.adapters.secure_score import SecureScoreAdapter
from gxassessms.core.domain.enums import (
    CoverageStatus,
    FindingStatus,
    ToolSource,
)
from gxassessms.core.domain.models import (
    ArtifactRecord,
    CoverageRecord,
    Finding,
    ResolvedManifest,
    ToolObservation,
)
from tests.conformance.adapter_suite import AdapterConformanceSuite

# Basenames the adapter expects when matching files in the manifest.
_PROFILES_BASENAME = "secureScoreControlProfiles.json"
_SCORES_BASENAME = "secureScores.json"


class TestSecureScoreConformance(AdapterConformanceSuite):
    """Secure Score conformance tests -- all assertions inherited."""

    @pytest.fixture
    def adapter(self) -> SecureScoreAdapter:
        return SecureScoreAdapter()

    @pytest.fixture
    def fixture_dir(self) -> Path:
        return (
            Path(__file__).parent.parent.parent
            / "src"
            / "gxassessms"
            / "adapters"
            / "secure_score"
            / "fixtures"
        )

    @pytest.fixture
    def resolved_manifest(
        self,
        adapter: SecureScoreAdapter,
        fixture_dir: Path,
        tmp_path: Path,
    ) -> ResolvedManifest:
        """Build a ResolvedManifest pointing at the Secure Score fixture files.

        The adapter matches files by basename (secureScoreControlProfiles.json
        and secureScores.json), so we copy the fixture data into a tmp_path
        with the expected names.
        """
        profiles_src = fixture_dir / "secure_score_profiles.json"
        scores_src = fixture_dir / "secure_score_snapshot.json"

        profiles_path = tmp_path / _PROFILES_BASENAME
        scores_path = tmp_path / _SCORES_BASENAME

        shutil.copy2(profiles_src, profiles_path)
        shutil.copy2(scores_src, scores_path)

        sha_profiles = hashlib.sha256(profiles_path.read_bytes()).hexdigest()
        sha_scores = hashlib.sha256(scores_path.read_bytes()).hexdigest()

        return ResolvedManifest(
            tool=ToolSource.SECURE_SCORE,
            tool_slug="secure-score",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={
                str(profiles_path): ArtifactRecord(
                    encoding="utf-8",
                    sha256=sha_profiles,
                ),
                str(scores_path): ArtifactRecord(
                    encoding="utf-8",
                    sha256=sha_scores,
                ),
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

    # ----- Secure Score-specific conformance tests -----

    def test_observation_ids_are_prefixed(
        self,
        observations: list[ToolObservation],
    ) -> None:
        """Secure Score observation IDs must follow secure_score:{control_id} format."""
        for obs in observations:
            assert obs.observation_id.startswith("secure_score:"), (
                f"observation_id must start with 'secure_score:': {obs.observation_id}"
            )

    def test_all_observations_have_secure_score_tool(
        self,
        observations: list[ToolObservation],
    ) -> None:
        for obs in observations:
            assert obs.tool == ToolSource.SECURE_SCORE

    def test_full_score_produces_pass_status(
        self,
        observations: list[ToolObservation],
    ) -> None:
        """MFARegistrationV2 has score == maxScore -> PASS."""
        mfa = next(o for o in observations if o.native_check_id == "MFARegistrationV2")
        assert mfa.native_status == FindingStatus.PASS

    def test_zero_score_produces_fail_status(
        self,
        observations: list[ToolObservation],
    ) -> None:
        """BlockLegacyAuthentication has score 0 -> FAIL."""
        block = next(o for o in observations if o.native_check_id == "BlockLegacyAuthentication")
        assert block.native_status == FindingStatus.FAIL

    def test_third_party_produces_not_applicable(
        self,
        observations: list[ToolObservation],
    ) -> None:
        """ThirdPartyIgnored has thirdParty state -> NOT_APPLICABLE."""
        tp = next(o for o in observations if o.native_check_id == "ThirdPartyIgnored")
        assert tp.native_status == FindingStatus.NOT_APPLICABLE

    def test_deprecated_controls_excluded(
        self,
        observations: list[ToolObservation],
    ) -> None:
        ids = [o.native_check_id for o in observations]
        assert "DeprecatedControl" not in ids

    def test_multiple_severities_in_fixture(
        self,
        observations: list[ToolObservation],
    ) -> None:
        """Fixture covers multiple severity levels."""
        severities = {obs.native_severity for obs in observations}
        assert len(severities) >= 2

    def test_multiple_statuses_in_fixture(
        self,
        observations: list[ToolObservation],
    ) -> None:
        """Fixture covers PASS, FAIL, and NOT_APPLICABLE at minimum."""
        statuses = {obs.native_status for obs in observations}
        assert len(statuses) >= 3

    def test_validate_raw_rejects_missing_value_key(
        self,
        adapter: SecureScoreAdapter,
        tmp_path: Path,
    ) -> None:
        """A profiles file without a 'value' key should fail validation."""
        bad_file = tmp_path / _PROFILES_BASENAME
        bad_file.write_text('{"notValue": []}')
        scores_file = tmp_path / _SCORES_BASENAME
        scores_file.write_text('{"value": []}')

        sha_bad = hashlib.sha256(bad_file.read_bytes()).hexdigest()
        sha_scores = hashlib.sha256(scores_file.read_bytes()).hexdigest()

        raw = ResolvedManifest(
            tool=ToolSource.SECURE_SCORE,
            tool_slug="secure-score",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={
                str(bad_file): ArtifactRecord(encoding="utf-8", sha256=sha_bad),
                str(scores_file): ArtifactRecord(encoding="utf-8", sha256=sha_scores),
            },
            execution_metadata={},
        )
        from gxassessms.core.contracts.errors import RawOutputValidationError

        with pytest.raises(RawOutputValidationError, match="missing required 'value' key"):
            adapter.validate_raw(raw)

    def test_validate_raw_rejects_missing_file(
        self,
        adapter: SecureScoreAdapter,
        tmp_path: Path,
    ) -> None:
        """A manifest with only one of the two required files should fail."""
        single_file = tmp_path / _SCORES_BASENAME
        single_file.write_text('{"value": []}')
        sha = hashlib.sha256(single_file.read_bytes()).hexdigest()

        raw = ResolvedManifest(
            tool=ToolSource.SECURE_SCORE,
            tool_slug="secure-score",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={
                str(single_file): ArtifactRecord(encoding="utf-8", sha256=sha),
            },
            execution_metadata={},
        )
        from gxassessms.core.contracts.errors import RawOutputValidationError

        with pytest.raises(RawOutputValidationError, match="Missing in Secure Score manifest"):
            adapter.validate_raw(raw)

    def test_validate_raw_rejects_empty_manifest(
        self,
        adapter: SecureScoreAdapter,
    ) -> None:
        """An empty file_manifest should fail validation."""
        from gxassessms.core.contracts.errors import RawOutputValidationError

        raw = ResolvedManifest(
            tool=ToolSource.SECURE_SCORE,
            tool_slug="secure-score",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={},
            execution_metadata={},
        )
        with pytest.raises(RawOutputValidationError, match="file manifest is empty"):
            adapter.validate_raw(raw)

    def test_validate_raw_rejects_non_list_value(
        self,
        adapter: SecureScoreAdapter,
        tmp_path: Path,
    ) -> None:
        """A file with 'value' as a dict (not a list) should fail validation."""
        from gxassessms.core.contracts.errors import RawOutputValidationError

        bad_file = tmp_path / _PROFILES_BASENAME
        bad_file.write_text('{"value": {"error": "not a list"}}')
        scores_file = tmp_path / _SCORES_BASENAME
        scores_file.write_text('{"value": []}')

        sha_bad = hashlib.sha256(bad_file.read_bytes()).hexdigest()
        sha_scores = hashlib.sha256(scores_file.read_bytes()).hexdigest()

        raw = ResolvedManifest(
            tool=ToolSource.SECURE_SCORE,
            tool_slug="secure-score",
            schema_version="1.0.0",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
            file_manifest={
                str(bad_file): ArtifactRecord(encoding="utf-8", sha256=sha_bad),
                str(scores_file): ArtifactRecord(encoding="utf-8", sha256=sha_scores),
            },
            execution_metadata={},
        )
        with pytest.raises(RawOutputValidationError, match="'value' is not a list"):
            adapter.validate_raw(raw)

    def test_coverage_returns_records(
        self,
        adapter: SecureScoreAdapter,
        resolved_manifest: ResolvedManifest,
    ) -> None:
        records = adapter.coverage(resolved_manifest)
        assert len(records) > 0
        for r in records:
            assert r.tool == ToolSource.SECURE_SCORE
            assert r.status == CoverageStatus.ASSESSED

    def test_coverage_records_unique_by_control(
        self,
        coverage_records: list[CoverageRecord] | None,
    ) -> None:
        """No duplicate control IDs in coverage output."""
        assert coverage_records is not None
        control_ids = [r.control_id for r in coverage_records]
        assert len(control_ids) == len(set(control_ids))

    def test_normalized_categories_match_control_category(
        self,
        normalized_findings: list[Finding],
    ) -> None:
        """Normalized findings get correct categories from CATEGORY_MAP,
        not the COMPLIANCE fallback. This is the end-to-end regression test
        for the native_category fix."""
        from gxassessms.core.domain.enums import Category

        category_by_id = {f.native_check_id: f.category for f in normalized_findings}

        # Identity controls -> IDENTITY_ACCESS
        assert category_by_id["MFARegistrationV2"] == Category.IDENTITY_ACCESS
        assert category_by_id["AdminMFAV2"] == Category.IDENTITY_ACCESS
        assert category_by_id["BlockLegacyAuthentication"] == Category.IDENTITY_ACCESS
        assert category_by_id["OneAdmin"] == Category.IDENTITY_ACCESS
        assert category_by_id["RoleOverlap"] == Category.IDENTITY_ACCESS

        # Data controls -> DATA_PROTECTION
        assert category_by_id["DLPEnabled"] == Category.DATA_PROTECTION
        assert category_by_id["NonOwnerAccess"] == Category.DATA_PROTECTION

        # Device controls -> DEVICE_MANAGEMENT
        assert category_by_id["ThirdPartyIgnored"] == Category.DEVICE_MANAGEMENT
