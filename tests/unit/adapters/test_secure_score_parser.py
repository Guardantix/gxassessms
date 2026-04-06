"""Tests for Secure Score parser -- joins two APIs into ToolObservations."""

import json
import logging
from pathlib import Path

import pytest

from gxassessms.adapters.secure_score.parser import (
    _derive_status,
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

    def test_returns_default_for_non_dict_entry(self) -> None:
        """Non-dict items in controlStateUpdates must not crash -- return 'Default'."""
        assert get_latest_control_state(["not_a_dict"]) == "Default"

    def test_returns_default_for_none_value_in_list(self) -> None:
        """None items in controlStateUpdates must not crash -- return 'Default'."""
        assert get_latest_control_state([None]) == "Default"


class TestDeriveStatus:
    def test_third_party_with_full_score_is_not_applicable(self) -> None:
        """thirdParty state overrides full score -- result is NOT_APPLICABLE, not PASS."""
        result = _derive_status(score=10.0, max_score=10.0, latest_state="thirdParty")
        assert result == FindingStatus.NOT_APPLICABLE

    def test_ignored_with_full_score_is_not_applicable(self) -> None:
        """ignored state overrides full score -- result is NOT_APPLICABLE, not PASS."""
        result = _derive_status(score=10.0, max_score=10.0, latest_state="ignored")
        assert result == FindingStatus.NOT_APPLICABLE

    def test_default_state_with_full_score_is_pass(self) -> None:
        """Default state with full score -> PASS (state check doesn't fire).

        This passes even before the fix -- it's a regression guard ensuring
        the fix doesn't break the Default/PASS path.
        """
        result = _derive_status(score=10.0, max_score=10.0, latest_state="Default")
        assert result == FindingStatus.PASS

    def test_none_score_is_always_manual(self) -> None:
        """None score -> MANUAL regardless of state.

        This passes even before the fix -- it's a regression guard ensuring
        the fix preserves the None score -> MANUAL path.
        """
        assert (
            _derive_status(score=None, max_score=10.0, latest_state="thirdParty")
            == FindingStatus.MANUAL
        )
        assert (
            _derive_status(score=None, max_score=10.0, latest_state="Default")
            == FindingStatus.MANUAL
        )

    def test_none_max_score_is_manual(self) -> None:
        """None maxScore -> MANUAL even when score data exists."""
        result = _derive_status(score=5.0, max_score=None, latest_state="Default")
        assert result == FindingStatus.MANUAL


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

    def test_missing_max_score_produces_manual(self) -> None:
        """Profile with no maxScore field produces MANUAL even when score data exists."""
        profiles = {
            "value": [
                {
                    "id": "NoMaxScore",
                    "title": "Control Without MaxScore",
                    "deprecated": False,
                    "rank": 10,
                    "tier": "Core",
                    "controlCategory": "Identity",
                    "controlStateUpdates": [],
                    # intentionally omitting "maxScore"
                }
            ]
        }
        scores = {"value": [{"controlScores": [{"controlName": "NoMaxScore", "score": 5.0}]}]}
        observations = parse_secure_score(profiles, scores)
        assert len(observations) == 1
        assert observations[0].native_status == FindingStatus.MANUAL

    def test_missing_rank_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Profile with no 'rank' field emits a warning log."""
        profiles = {
            "value": [
                {
                    "id": "NoRankControl",
                    "title": "Control Without Rank",
                    "deprecated": False,
                    "tier": "Core",
                    "controlCategory": "Identity",
                    "maxScore": 5.0,
                    "controlStateUpdates": [],
                    # intentionally omitting "rank"
                }
            ]
        }
        with caplog.at_level(logging.WARNING, logger="gxassessms.adapters.secure_score.parser"):
            parse_secure_score(profiles, {"value": []})
        assert "rank" in caplog.text.lower()

    def test_missing_tier_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Profile with no 'tier' field emits a warning log."""
        profiles = {
            "value": [
                {
                    "id": "NoTierControl",
                    "title": "Control Without Tier",
                    "deprecated": False,
                    "rank": 10,
                    "controlCategory": "Identity",
                    "maxScore": 5.0,
                    "controlStateUpdates": [],
                    # intentionally omitting "tier"
                }
            ]
        }
        with caplog.at_level(logging.WARNING, logger="gxassessms.adapters.secure_score.parser"):
            parse_secure_score(profiles, {"value": []})
        assert "tier" in caplog.text.lower()

    def test_empty_profiles_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Empty profiles array emits a warning log."""
        empty = {"value": []}
        with caplog.at_level(logging.WARNING, logger="gxassessms.adapters.secure_score.parser"):
            parse_secure_score(empty, {"value": []})
        assert "empty list" in caplog.text.lower()

    def test_empty_scores_logs_warning(
        self, caplog: pytest.LogCaptureFixture, profiles_data: dict
    ) -> None:
        """Empty scores response emits a warning log."""
        with caplog.at_level(logging.WARNING, logger="gxassessms.adapters.secure_score.parser"):
            parse_secure_score(profiles_data, {"value": []})
        assert "no records" in caplog.text.lower()
