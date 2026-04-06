"""Tests for Secure Score declarative mappings -- data completeness and consistency."""

import json
from pathlib import Path

import pytest

from gxassessms.adapters.secure_score.mappings import (
    CATEGORY_MAP,
    CONTROL_STATE_PASS_THROUGH,
    derive_severity,
)
from gxassessms.core.domain.enums import Category, Severity


@pytest.fixture
def profiles_data() -> list[dict]:
    """Load the Secure Score control profiles fixture."""
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
        data = json.load(f)
    return data["value"]


class TestCategoryMap:
    def test_category_map_is_dict(self) -> None:
        assert isinstance(CATEGORY_MAP, dict)

    def test_category_map_values_are_valid_categories(self) -> None:
        for category in CATEGORY_MAP.values():
            assert isinstance(category, Category)

    def test_all_five_categories_mapped(self) -> None:
        assert "Identity" in CATEGORY_MAP
        assert "Data" in CATEGORY_MAP
        assert "Device" in CATEGORY_MAP
        assert "Apps" in CATEGORY_MAP
        assert "Infrastructure" in CATEGORY_MAP
        assert len(CATEGORY_MAP) == 5

    def test_identity_maps_correctly(self) -> None:
        assert CATEGORY_MAP["Identity"] == Category.IDENTITY_ACCESS

    def test_data_maps_correctly(self) -> None:
        assert CATEGORY_MAP["Data"] == Category.DATA_PROTECTION

    def test_device_maps_correctly(self) -> None:
        assert CATEGORY_MAP["Device"] == Category.DEVICE_MANAGEMENT

    def test_apps_maps_correctly(self) -> None:
        assert CATEGORY_MAP["Apps"] == Category.COMPLIANCE

    def test_infrastructure_maps_correctly(self) -> None:
        assert CATEGORY_MAP["Infrastructure"] == Category.INFRASTRUCTURE_SECURITY

    def test_fixture_categories_covered(self, profiles_data: list[dict]) -> None:
        unmapped: set[str] = set()
        for profile in profiles_data:
            cat = profile["controlCategory"]
            if cat not in CATEGORY_MAP:
                unmapped.add(cat)
        assert unmapped == set(), f"Unmapped categories: {unmapped}"


class TestDeriveSeverity:
    def test_core_low_rank_is_critical(self) -> None:
        assert derive_severity(rank=1, tier="Core") == Severity.CRITICAL

    def test_core_rank_20_is_critical(self) -> None:
        assert derive_severity(rank=20, tier="Core") == Severity.CRITICAL

    def test_core_rank_21_is_high(self) -> None:
        assert derive_severity(rank=21, tier="Core") == Severity.HIGH

    def test_core_rank_50_is_high(self) -> None:
        assert derive_severity(rank=50, tier="Core") == Severity.HIGH

    def test_defense_in_depth_low_rank_is_high(self) -> None:
        assert derive_severity(rank=15, tier="Defense in Depth") == Severity.HIGH

    def test_defense_in_depth_rank_30_is_high(self) -> None:
        assert derive_severity(rank=30, tier="Defense in Depth") == Severity.HIGH

    def test_defense_in_depth_rank_31_is_medium(self) -> None:
        assert derive_severity(rank=31, tier="Defense in Depth") == Severity.MEDIUM

    def test_defense_in_depth_rank_60_is_medium(self) -> None:
        assert derive_severity(rank=60, tier="Defense in Depth") == Severity.MEDIUM

    def test_advanced_low_rank_is_medium(self) -> None:
        assert derive_severity(rank=10, tier="Advanced") == Severity.MEDIUM

    def test_advanced_rank_40_is_medium(self) -> None:
        assert derive_severity(rank=40, tier="Advanced") == Severity.MEDIUM

    def test_advanced_rank_41_is_low(self) -> None:
        assert derive_severity(rank=41, tier="Advanced") == Severity.LOW

    def test_unknown_tier_is_info(self) -> None:
        assert derive_severity(rank=1, tier="UnknownTier") == Severity.INFO

    def test_fixture_profiles_produce_valid_severities(
        self,
        profiles_data: list[dict],
    ) -> None:
        for profile in profiles_data:
            sev = derive_severity(rank=profile["rank"], tier=profile["tier"])
            assert isinstance(sev, Severity), f"Profile {profile['id']} produced invalid severity"


class TestControlStatePassThrough:
    def test_ignored_is_pass_through(self) -> None:
        assert "ignored" in CONTROL_STATE_PASS_THROUGH

    def test_third_party_is_pass_through(self) -> None:
        assert "thirdParty" in CONTROL_STATE_PASS_THROUGH

    def test_default_is_not_pass_through(self) -> None:
        assert "Default" not in CONTROL_STATE_PASS_THROUGH

    def test_reviewed_is_not_pass_through(self) -> None:
        assert "reviewed" not in CONTROL_STATE_PASS_THROUGH

    def test_is_frozenset(self) -> None:
        assert isinstance(CONTROL_STATE_PASS_THROUGH, frozenset)
