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
    """Maps (OCSF severity, canonical status) -> domain Severity enum."""

    def test_severity_map_is_dict(self) -> None:
        assert isinstance(SEVERITY_MAP, dict)

    def test_severity_map_keys_are_tuples(self) -> None:
        for key in SEVERITY_MAP:
            assert isinstance(key, tuple), f"Key {key!r} must be a tuple"
            assert len(key) == 2, f"Key {key!r} must have 2 elements"

    def test_severity_map_values_are_valid_severities(self) -> None:
        for severity in SEVERITY_MAP.values():
            assert isinstance(severity, Severity)

    def test_ocsf_severity_fail_mappings(self) -> None:
        """Prowler OCSF severity strings (title case) with FAIL status."""
        assert SEVERITY_MAP[("Critical", "FAIL")] == Severity.CRITICAL
        assert SEVERITY_MAP[("High", "FAIL")] == Severity.HIGH
        assert SEVERITY_MAP[("Medium", "FAIL")] == Severity.MEDIUM
        assert SEVERITY_MAP[("Low", "FAIL")] == Severity.LOW
        assert SEVERITY_MAP[("Informational", "FAIL")] == Severity.LOW

    def test_ocsf_severity_manual_mappings(self) -> None:
        """MANUAL status entries preserve reported severity."""
        assert SEVERITY_MAP[("Critical", "MANUAL")] == Severity.CRITICAL
        assert SEVERITY_MAP[("High", "MANUAL")] == Severity.HIGH
        assert SEVERITY_MAP[("Medium", "MANUAL")] == Severity.MEDIUM

    def test_fixture_severities_covered(self, fixture_data: list[dict]) -> None:
        """Every (severity, status_code) in fixtures has a SEVERITY_MAP entry."""
        severity_keys = {k[0] for k in SEVERITY_MAP}
        unmapped: set[str] = set()
        for finding in fixture_data:
            sev = finding["severity"]
            if sev not in severity_keys:
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
    """Maps check ID (metadata.event_code) -> domain Category enum."""

    def test_category_map_is_dict(self) -> None:
        assert isinstance(CATEGORY_MAP, dict)

    def test_category_map_values_are_valid_categories(self) -> None:
        for category in CATEGORY_MAP.values():
            assert isinstance(category, Category)

    def test_known_check_id_mappings(self) -> None:
        assert (
            CATEGORY_MAP["defender_ensure_defender_for_app_services_is_on"]
            == Category.INFRASTRUCTURE_SECURITY
        )
        assert (
            CATEGORY_MAP["iam_subscription_roles_owner_custom_not_created"]
            == Category.IDENTITY_ACCESS
        )
        assert CATEGORY_MAP["sqlserver_auditing_enabled"] == Category.DATA_PROTECTION
        assert (
            CATEGORY_MAP["storage_secure_transfer_required_is_enabled"] == Category.DATA_PROTECTION
        )

    def test_all_dedup_keys_have_category(self) -> None:
        """Every check in DEDUP_KEY_RULES should have a CATEGORY_MAP entry."""
        missing = set(DEDUP_KEY_RULES) - set(CATEGORY_MAP)
        assert missing == set(), f"Checks in DEDUP_KEY_RULES missing from CATEGORY_MAP: {missing}"

    def test_fixture_check_ids_covered(self, fixture_data: list[dict]) -> None:
        """Every metadata.event_code in fixtures has a matching category."""
        unmapped: set[str] = set()
        for finding in fixture_data:
            check_id = finding.get("metadata", {}).get("event_code")
            if check_id and check_id not in CATEGORY_MAP:
                unmapped.add(check_id)
        assert unmapped == set(), f"Unmapped check IDs: {unmapped}"


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
