"""Tests for Secure Score parser -- joins two APIs into ToolObservations."""

import json
from pathlib import Path

import pytest

from gxassessms.adapters.secure_score.parser import (
    get_latest_control_state,
    parse_secure_score,
)
from gxassessms.core.domain.enums import FindingStatus, Severity, ToolSource
from gxassessms.core.domain.models import ToolObservation


@pytest.fixture
def profiles_data() -> dict:
    """Load the Secure Score control profiles fixture (full API response)."""
    fixture_path = (
        Path(__file__).parent.parent.parent.parent
        / "src"
        / "gxassessms"
        / "adapters"
        / "secure_score"
        / "fixtures"
        / "secure_score_profiles.json"
    )
    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def snapshot_data() -> dict:
    """Load the Secure Score snapshot fixture (full API response)."""
    fixture_path = (
        Path(__file__).parent.parent.parent.parent
        / "src"
        / "gxassessms"
        / "adapters"
        / "secure_score"
        / "fixtures"
        / "secure_score_snapshot.json"
    )
    with open(fixture_path) as f:
        return json.load(f)


class TestGetLatestControlState:
    def test_returns_state_from_single_update(self) -> None:
        updates = [
            {"state": "Default", "assignedTo": None, "updatedDateTime": "2026-01-10T08:00:00Z"}
        ]
        assert get_latest_control_state(updates) == "Default"

    def test_returns_latest_by_datetime(self) -> None:
        updates = [
            {"state": "Default", "updatedDateTime": "2026-01-10T08:00:00Z"},
            {"state": "thirdParty", "updatedDateTime": "2026-02-15T09:00:00Z"},
        ]
        assert get_latest_control_state(updates) == "thirdParty"

    def test_returns_default_for_empty(self) -> None:
        assert get_latest_control_state([]) == "Default"

    def test_returns_default_for_none(self) -> None:
        assert get_latest_control_state(None) == "Default"


class TestParseSecureScore:
    def test_returns_list_of_tool_observations(
        self, profiles_data: dict, snapshot_data: dict
    ) -> None:
        observations = parse_secure_score(profiles_data, snapshot_data)
        assert isinstance(observations, list)
        assert all(isinstance(o, ToolObservation) for o in observations)

    def test_deprecated_controls_excluded(self, profiles_data: dict, snapshot_data: dict) -> None:
        observations = parse_secure_score(profiles_data, snapshot_data)
        obs_ids = [o.native_check_id for o in observations]
        assert "DeprecatedControl" not in obs_ids

    def test_non_deprecated_controls_included(
        self, profiles_data: dict, snapshot_data: dict
    ) -> None:
        observations = parse_secure_score(profiles_data, snapshot_data)
        obs_ids = [o.native_check_id for o in observations]
        assert "MFARegistrationV2" in obs_ids
        assert "AdminMFAV2" in obs_ids
        assert "BlockLegacyAuthentication" in obs_ids
        assert "DLPEnabled" in obs_ids
        assert "NonOwnerAccess" in obs_ids

    def test_observation_count(self, profiles_data: dict, snapshot_data: dict) -> None:
        observations = parse_secure_score(profiles_data, snapshot_data)
        assert len(observations) == 8  # 9 profiles minus 1 deprecated

    def test_pass_status_for_full_score(self, profiles_data: dict, snapshot_data: dict) -> None:
        """MFARegistrationV2: score=10.0, maxScore=10.0 -> PASS."""
        observations = parse_secure_score(profiles_data, snapshot_data)
        mfa = next(o for o in observations if o.native_check_id == "MFARegistrationV2")
        assert mfa.native_status == FindingStatus.PASS

    def test_fail_status_for_zero_score(self, profiles_data: dict, snapshot_data: dict) -> None:
        """BlockLegacyAuthentication: score=0.0, maxScore=8.0 -> FAIL."""
        observations = parse_secure_score(profiles_data, snapshot_data)
        block = next(o for o in observations if o.native_check_id == "BlockLegacyAuthentication")
        assert block.native_status == FindingStatus.FAIL

    def test_not_applicable_for_third_party(self, profiles_data: dict, snapshot_data: dict) -> None:
        """ThirdPartyIgnored: state='thirdParty', score=0 -> NOT_APPLICABLE."""
        observations = parse_secure_score(profiles_data, snapshot_data)
        tp = next(o for o in observations if o.native_check_id == "ThirdPartyIgnored")
        assert tp.native_status == FindingStatus.NOT_APPLICABLE

    def test_severity_from_rank_and_tier(self, profiles_data: dict, snapshot_data: dict) -> None:
        observations = parse_secure_score(profiles_data, snapshot_data)
        mfa = next(o for o in observations if o.native_check_id == "MFARegistrationV2")
        assert mfa.native_severity == Severity.CRITICAL  # rank=1, Core
        dlp = next(o for o in observations if o.native_check_id == "DLPEnabled")
        assert dlp.native_severity == Severity.HIGH  # rank=35, Core
        role = next(o for o in observations if o.native_check_id == "RoleOverlap")
        assert role.native_severity == Severity.LOW  # rank=42, Advanced
        noa = next(o for o in observations if o.native_check_id == "NonOwnerAccess")
        assert noa.native_severity == Severity.MEDIUM  # rank=55, Defense in Depth

    def test_title_from_profile(self, profiles_data: dict, snapshot_data: dict) -> None:
        observations = parse_secure_score(profiles_data, snapshot_data)
        mfa = next(o for o in observations if o.native_check_id == "MFARegistrationV2")
        assert mfa.title == "Ensure all users are registered for multi-factor authentication"

    def test_description_includes_remediation(
        self, profiles_data: dict, snapshot_data: dict
    ) -> None:
        observations = parse_secure_score(profiles_data, snapshot_data)
        mfa = next(o for o in observations if o.native_check_id == "MFARegistrationV2")
        assert "Microsoft Entra ID" in mfa.description

    def test_observation_id_format(self, profiles_data: dict, snapshot_data: dict) -> None:
        observations = parse_secure_score(profiles_data, snapshot_data)
        mfa = next(o for o in observations if o.native_check_id == "MFARegistrationV2")
        assert mfa.observation_id == "secure_score:MFARegistrationV2"

    def test_tool_is_secure_score(self, profiles_data: dict, snapshot_data: dict) -> None:
        observations = parse_secure_score(profiles_data, snapshot_data)
        for obs in observations:
            assert obs.tool == ToolSource.SECURE_SCORE

    def test_raw_data_contains_profile_and_score(
        self, profiles_data: dict, snapshot_data: dict
    ) -> None:
        observations = parse_secure_score(profiles_data, snapshot_data)
        mfa = next(o for o in observations if o.native_check_id == "MFARegistrationV2")
        assert "profile" in mfa.raw_data
        assert "score_data" in mfa.raw_data
        assert mfa.raw_data["profile"]["tier"] == "Core"
        assert mfa.raw_data["score_data"]["score"] == 10.0

    def test_empty_profiles(self, snapshot_data: dict) -> None:
        empty = {"value": []}
        assert parse_secure_score(empty, snapshot_data) == []

    def test_empty_scores(self, profiles_data: dict) -> None:
        """Profiles with no scores -> all get MANUAL status."""
        empty = {"value": []}
        observations = parse_secure_score(profiles_data, empty)
        non_deprecated = [o for o in observations if o.native_check_id != "DeprecatedControl"]
        for obs in non_deprecated:
            assert obs.native_status == FindingStatus.MANUAL

    def test_pass_full_score_nonowner(self, profiles_data: dict, snapshot_data: dict) -> None:
        """NonOwnerAccess: score=4.0, maxScore=4.0 -> PASS."""
        observations = parse_secure_score(profiles_data, snapshot_data)
        noa = next(o for o in observations if o.native_check_id == "NonOwnerAccess")
        assert noa.native_status == FindingStatus.PASS

    def test_native_category_from_control_category(
        self, profiles_data: dict, snapshot_data: dict
    ) -> None:
        """Parser sets native_category from profile controlCategory field."""
        observations = parse_secure_score(profiles_data, snapshot_data)
        mfa = next(o for o in observations if o.native_check_id == "MFARegistrationV2")
        assert mfa.native_category == "Identity"
        dlp = next(o for o in observations if o.native_check_id == "DLPEnabled")
        assert dlp.native_category == "Data"
        tp = next(o for o in observations if o.native_check_id == "ThirdPartyIgnored")
        assert tp.native_category == "Device"
