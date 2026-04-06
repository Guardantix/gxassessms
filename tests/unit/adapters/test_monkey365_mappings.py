"""Tests for Monkey365 declarative mappings -- data completeness and consistency."""

import json
from pathlib import Path

import pytest

from gxassessms.adapters.monkey365.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
    SEVERITY_MAP,
    STATUS_MAP,
)
from gxassessms.core.domain.enums import Category, Severity


@pytest.fixture
def fixture_data() -> list[dict]:
    """Load the Monkey365 OCSF fixture data."""
    fixture_path = (
        Path(__file__).parent.parent.parent.parent
        / "src"
        / "gxassessms"
        / "adapters"
        / "monkey365"
        / "fixtures"
        / "monkey365_sample.json"
    )
    with open(fixture_path) as f:
        return json.load(f)


class TestSeverityMap:
    """Maps OCSF severity string -> domain Severity enum."""

    def test_severity_map_is_dict(self) -> None:
        assert isinstance(SEVERITY_MAP, dict)

    def test_severity_map_values_are_valid_severities(self) -> None:
        for severity in SEVERITY_MAP.values():
            assert isinstance(severity, Severity)

    def test_ocsf_severity_mappings(self) -> None:
        """Monkey365 OCSF severity strings (title case)."""
        assert SEVERITY_MAP["Critical"] == Severity.CRITICAL
        assert SEVERITY_MAP["High"] == Severity.HIGH
        assert SEVERITY_MAP["Medium"] == Severity.MEDIUM
        assert SEVERITY_MAP["Low"] == Severity.LOW
        assert SEVERITY_MAP["Informational"] == Severity.INFO
        assert SEVERITY_MAP["Unknown"] == Severity.INFO  # Unknown -> INFO (conservative)

    def test_fixture_severities_covered(self, fixture_data: list[dict]) -> None:
        """Every severity value in fixtures is in SEVERITY_MAP."""
        unmapped: set[str] = set()
        for finding in fixture_data:
            sev = finding["severity"]
            if sev not in SEVERITY_MAP:
                unmapped.add(sev)
        assert unmapped == set(), f"Unmapped severities in fixtures: {unmapped}"


class TestStatusMap:
    """Maps OCSF statusCode -> domain FindingStatus enum."""

    def test_pass_maps_to_pass(self) -> None:
        from gxassessms.core.domain.enums import FindingStatus

        assert STATUS_MAP["pass"] == FindingStatus.PASS

    def test_fail_maps_to_fail(self) -> None:
        from gxassessms.core.domain.enums import FindingStatus

        assert STATUS_MAP["fail"] == FindingStatus.FAIL

    def test_manual_maps_to_manual(self) -> None:
        from gxassessms.core.domain.enums import FindingStatus

        assert STATUS_MAP["manual"] == FindingStatus.MANUAL

    def test_all_three_statuses_present(self) -> None:
        assert len(STATUS_MAP) == 3

    def test_fixture_statuses_covered(self, fixture_data: list[dict]) -> None:
        """Every statusCode value in fixtures is in STATUS_MAP."""
        unmapped: set[str] = set()
        for finding in fixture_data:
            sc = finding["statusCode"]
            if sc not in STATUS_MAP:
                unmapped.add(sc)
        assert unmapped == set(), f"Unmapped statusCodes: {unmapped}"


class TestCategoryMap:
    """Maps resources.group.name -> domain Category enum."""

    def test_category_map_is_dict(self) -> None:
        assert isinstance(CATEGORY_MAP, dict)

    def test_category_map_values_are_valid_categories(self) -> None:
        for category in CATEGORY_MAP.values():
            assert isinstance(category, Category)

    def test_known_group_name_mappings(self) -> None:
        assert CATEGORY_MAP["Entra Identity Governance"] == Category.IDENTITY_ACCESS
        assert CATEGORY_MAP["Exchange Online"] == Category.EMAIL_COLLABORATION
        assert CATEGORY_MAP["SharePoint Online"] == Category.DATA_PROTECTION
        assert CATEGORY_MAP["Microsoft Teams"] == Category.EMAIL_COLLABORATION

    def test_fixture_groups_covered(self, fixture_data: list[dict]) -> None:
        """Every resources.group.name in fixtures has a matching category."""
        unmapped: set[str] = set()
        for finding in fixture_data:
            group_name = finding.get("resources", {}).get("group", {}).get("name")
            if group_name and group_name not in CATEGORY_MAP:
                unmapped.add(group_name)
        assert unmapped == set(), f"Unmapped group names: {unmapped}"


class TestDedupKeyRules:
    def test_dedup_key_rules_is_dict(self) -> None:
        assert isinstance(DEDUP_KEY_RULES, dict)

    def test_dedup_key_values_are_namespaced(self) -> None:
        for key, value in DEDUP_KEY_RULES.items():
            assert ":" in value, f"Dedup key for {key} must be namespaced (contain ':')"

    def test_known_mappings_present(self) -> None:
        """Verified against Monkey365 rule definitions and CIS crossref."""
        assert DEDUP_KEY_RULES["aad_cap_force_mfa_high_users"] == "cis:m365:5.2.2.1"
        assert DEDUP_KEY_RULES["aad_cap_force_mfa_all_users"] == "cis:m365:5.2.2.2"

    def test_keys_are_monkey365_idsuffix_format(self) -> None:
        """Monkey365 idSuffix values use underscore-separated lowercase."""
        for key in DEDUP_KEY_RULES:
            assert key == key.lower(), f"Dedup key {key} must be lowercase"
            assert "." not in key, f"Dedup key {key} must not contain dots (use underscores)"
