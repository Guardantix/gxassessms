"""Tests for Prowler declarative mappings -- data completeness and consistency."""

from __future__ import annotations

from typing import Any

import pytest

from gxassessms.adapters.prowler.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
    SEVERITY_MAP,
    STATUS_MAP,
)
from gxassessms.core.domain.enums import Category, Severity


@pytest.fixture
def fixture_data(prowler_fixture_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Alias for shared prowler_fixture_data fixture."""
    return prowler_fixture_data


class TestSeverityMap:
    """Maps OCSF severity string -> domain Severity enum."""

    def test_severity_map_is_dict(self) -> None:
        assert isinstance(SEVERITY_MAP, dict)

    def test_severity_map_values_are_valid_severities(self) -> None:
        for severity in SEVERITY_MAP.values():
            assert isinstance(severity, Severity)

    def test_ocsf_severity_mappings(self) -> None:
        """Prowler OCSF severity strings (title case)."""
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
    """Maps OCSF status_code -> domain FindingStatus enum."""

    def test_pass_maps_to_pass(self) -> None:
        from gxassessms.core.domain.enums import FindingStatus

        assert STATUS_MAP["PASS"] == FindingStatus.PASS

    def test_fail_maps_to_fail(self) -> None:
        from gxassessms.core.domain.enums import FindingStatus

        assert STATUS_MAP["FAIL"] == FindingStatus.FAIL

    def test_manual_maps_to_manual(self) -> None:
        from gxassessms.core.domain.enums import FindingStatus

        assert STATUS_MAP["MANUAL"] == FindingStatus.MANUAL

    def test_all_three_statuses_present(self) -> None:
        assert len(STATUS_MAP) == 3

    def test_fixture_statuses_covered(self, fixture_data: list[dict]) -> None:
        """Every status_code value in fixtures is in STATUS_MAP."""
        unmapped: set[str] = set()
        for finding in fixture_data:
            sc = finding["status_code"]
            if sc not in STATUS_MAP:
                unmapped.add(sc)
        assert unmapped == set(), f"Unmapped status_codes: {unmapped}"


class TestCategoryMap:
    """Maps resources[0].group.name -> domain Category enum."""

    def test_category_map_is_dict(self) -> None:
        assert isinstance(CATEGORY_MAP, dict)

    def test_category_map_values_are_valid_categories(self) -> None:
        for category in CATEGORY_MAP.values():
            assert isinstance(category, Category)

    def test_known_group_name_mappings(self) -> None:
        assert CATEGORY_MAP["defender"] == Category.INFRASTRUCTURE_SECURITY
        assert CATEGORY_MAP["iam"] == Category.IDENTITY_ACCESS
        assert CATEGORY_MAP["sqlserver"] == Category.DATA_PROTECTION
        assert CATEGORY_MAP["storage"] == Category.DATA_PROTECTION

    def test_fixture_groups_covered(self, fixture_data: list[dict]) -> None:
        """Every resources[0].group.name in fixtures has a matching category."""
        unmapped: set[str] = set()
        for finding in fixture_data:
            resources = finding.get("resources", [])
            if resources:
                group_name = resources[0].get("group", {}).get("name")
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
        """Verified against Prowler check definitions and CIS Azure crossref."""
        assert (
            DEDUP_KEY_RULES["defender_ensure_defender_for_app_services_is_on"] == "cis:azure:5.3.1"
        )
        assert DEDUP_KEY_RULES["storage_secure_transfer_required_is_enabled"] == "cis:azure:3.1"

    def test_keys_are_prowler_check_id_format(self) -> None:
        """Prowler check IDs use underscore-separated lowercase, no hyphens."""
        for key in DEDUP_KEY_RULES:
            assert key == key.lower(), f"Dedup key {key} must be lowercase"
            assert "-" not in key, f"Dedup key {key} must not contain hyphens"
            assert "." not in key, f"Dedup key {key} must not contain dots"
