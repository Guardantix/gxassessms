"""Tests for Azure Advisor declarative mappings -- data completeness and consistency."""

import json
from pathlib import Path

import pytest

from gxassessms.adapters.azure_advisor.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
    IMPACT_TO_SEVERITY_MAP,
)
from gxassessms.core.domain.enums import Category, Severity


@pytest.fixture
def fixture_data() -> dict:
    """Load the Azure Advisor fixture data."""
    fixture_path = (
        Path(__file__).parent.parent.parent.parent
        / "src"
        / "gxassessms"
        / "adapters"
        / "azure_advisor"
        / "fixtures"
        / "azure_advisor_sample.json"
    )
    with open(fixture_path) as f:
        return json.load(f)


class TestImpactToSeverityMap:
    """Maps Azure Advisor impact string -> domain Severity enum.

    Azure Advisor has no native severity -- impact is the closest analog.
    """

    def test_map_is_dict(self) -> None:
        assert isinstance(IMPACT_TO_SEVERITY_MAP, dict)

    def test_map_values_are_valid_severities(self) -> None:
        for severity in IMPACT_TO_SEVERITY_MAP.values():
            assert isinstance(severity, Severity)

    def test_impact_mappings(self) -> None:
        """Azure Advisor impact levels (title case)."""
        assert IMPACT_TO_SEVERITY_MAP["High"] == Severity.HIGH
        assert IMPACT_TO_SEVERITY_MAP["Medium"] == Severity.MEDIUM
        assert IMPACT_TO_SEVERITY_MAP["Low"] == Severity.LOW

    def test_all_three_impacts_present(self) -> None:
        assert len(IMPACT_TO_SEVERITY_MAP) == 3

    def test_fixture_impacts_covered(self, fixture_data: dict) -> None:
        """Every impact value in fixtures is in IMPACT_TO_SEVERITY_MAP."""
        unmapped: set[str] = set()
        for rec in fixture_data["value"]:
            impact = rec["impact"]
            if impact not in IMPACT_TO_SEVERITY_MAP:
                unmapped.add(impact)
        assert unmapped == set(), f"Unmapped impacts in fixtures: {unmapped}"


class TestCategoryMap:
    """Maps Azure Advisor category string -> domain Category enum."""

    def test_category_map_is_dict(self) -> None:
        assert isinstance(CATEGORY_MAP, dict)

    def test_category_map_values_are_valid_categories(self) -> None:
        for category in CATEGORY_MAP.values():
            assert isinstance(category, Category)

    def test_known_category_mappings(self) -> None:
        assert CATEGORY_MAP["Security"] == Category.INFRASTRUCTURE_SECURITY
        assert CATEGORY_MAP["HighAvailability"] == Category.INFRASTRUCTURE_SECURITY
        assert CATEGORY_MAP["Performance"] == Category.OPERATIONAL_EXCELLENCE
        assert CATEGORY_MAP["Cost"] == Category.COST_OPTIMIZATION
        assert CATEGORY_MAP["OperationalExcellence"] == Category.OPERATIONAL_EXCELLENCE

    def test_all_five_categories_present(self) -> None:
        assert len(CATEGORY_MAP) == 5

    def test_fixture_categories_covered(self, fixture_data: dict) -> None:
        """Every category value in fixtures is in CATEGORY_MAP."""
        unmapped: set[str] = set()
        for rec in fixture_data["value"]:
            cat = rec["category"]
            if cat not in CATEGORY_MAP:
                unmapped.add(cat)
        assert unmapped == set(), f"Unmapped categories in fixtures: {unmapped}"


class TestDedupKeyRules:
    """Azure Advisor uses recommendationTypeId GUIDs as its native check IDs.

    Dedup keys map known recommendationTypeIds to a shared namespace.
    Azure Advisor is NOT CIS-aligned, so keys use the advisor: namespace.
    """

    def test_dedup_key_rules_is_dict(self) -> None:
        assert isinstance(DEDUP_KEY_RULES, dict)

    def test_dedup_key_values_are_namespaced(self) -> None:
        for key, value in DEDUP_KEY_RULES.items():
            assert ":" in value, f"Dedup key for {key} must be namespaced (contain ':')"

    def test_keys_are_lowercase_guids(self) -> None:
        """recommendationTypeId values are lowercase GUIDs."""
        import re

        guid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        for key in DEDUP_KEY_RULES:
            assert guid_pattern.match(key), f"Dedup key {key!r} is not a valid lowercase GUID"
