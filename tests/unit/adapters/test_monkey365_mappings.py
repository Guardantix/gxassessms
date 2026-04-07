"""Tests for Monkey365 declarative mappings -- data completeness and consistency."""

import json
from pathlib import Path
from typing import Any

import pytest

from gxassessms.adapters.monkey365.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
    SEVERITY_MAP,
    STATUS_MAP,
)
from gxassessms.core.domain.enums import Category, FindingStatus, Severity


@pytest.fixture(scope="module")
def fixture_data() -> list[dict[str, Any]]:
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
    """Maps (OCSF severity, canonical status) -> domain Severity enum."""

    def test_severity_map_is_dict(self) -> None:
        assert isinstance(SEVERITY_MAP, dict)

    def test_severity_map_keys_are_tuples(self) -> None:
        for key in SEVERITY_MAP:
            assert isinstance(key, tuple)
            assert len(key) == 2

    def test_severity_map_values_are_valid_severities(self) -> None:
        for severity in SEVERITY_MAP.values():
            assert isinstance(severity, Severity)

    def test_ocsf_severity_fail_mappings(self) -> None:
        """OCSF severity + FAIL -> expected domain severity."""
        assert SEVERITY_MAP[("Critical", FindingStatus.FAIL)] == Severity.CRITICAL
        assert SEVERITY_MAP[("High", FindingStatus.FAIL)] == Severity.HIGH
        assert SEVERITY_MAP[("Medium", FindingStatus.FAIL)] == Severity.MEDIUM
        assert SEVERITY_MAP[("Low", FindingStatus.FAIL)] == Severity.LOW
        assert SEVERITY_MAP[("Informational", FindingStatus.FAIL)] == Severity.INFO
        assert SEVERITY_MAP[("Unknown", FindingStatus.FAIL)] == Severity.INFO

    def test_ocsf_severity_manual_mappings(self) -> None:
        """MANUAL observations get same severity as FAIL (check importance, not result)."""
        assert SEVERITY_MAP[("Critical", FindingStatus.MANUAL)] == Severity.CRITICAL
        assert SEVERITY_MAP[("High", FindingStatus.MANUAL)] == Severity.HIGH
        assert SEVERITY_MAP[("Low", FindingStatus.MANUAL)] == Severity.LOW

    def test_fixture_severities_covered(self, fixture_data: list[dict[str, Any]]) -> None:
        """Every severity value in fixtures appears in at least one SEVERITY_MAP key."""
        mapped_severities = {key[0] for key in SEVERITY_MAP}
        unmapped: set[str] = set()
        for finding in fixture_data:
            sev = finding["severity"]
            if sev not in mapped_severities:
                unmapped.add(sev)
        assert unmapped == set(), f"Unmapped severities in fixtures: {unmapped}"


class TestStatusMap:
    """Maps OCSF statusCode -> domain FindingStatus enum."""

    def test_pass_maps_to_pass(self) -> None:
        assert STATUS_MAP["pass"] == FindingStatus.PASS

    def test_fail_maps_to_fail(self) -> None:
        assert STATUS_MAP["fail"] == FindingStatus.FAIL

    def test_manual_maps_to_manual(self) -> None:
        assert STATUS_MAP["manual"] == FindingStatus.MANUAL

    def test_all_three_statuses_present(self) -> None:
        assert len(STATUS_MAP) == 3

    def test_fixture_statuses_covered(self, fixture_data: list[dict[str, Any]]) -> None:
        """Every statusCode value in fixtures is in STATUS_MAP."""
        unmapped: set[str] = set()
        for finding in fixture_data:
            sc = finding["statusCode"]
            if sc not in STATUS_MAP:
                unmapped.add(sc)
        assert unmapped == set(), f"Unmapped statusCodes: {unmapped}"


class TestCategoryMap:
    """Maps module prefix (from native_check_id) -> domain Category enum.

    Only contains Monkey365-specific prefixes not already in default_category_map.
    Prefixes like aad, exo, azure are handled by the default map.
    """

    def test_category_map_is_dict(self) -> None:
        assert isinstance(CATEGORY_MAP, dict)

    def test_category_map_values_are_valid_categories(self) -> None:
        for category in CATEGORY_MAP.values():
            assert isinstance(category, Category)

    def test_monkey365_specific_prefix_mappings(self) -> None:
        """Prefixes unique to Monkey365 that extend the default category map."""
        assert CATEGORY_MAP["eid"] == Category.IDENTITY_ACCESS
        assert CATEGORY_MAP["spo"] == Category.DATA_PROTECTION
        assert CATEGORY_MAP["odb"] == Category.DATA_PROTECTION
        assert CATEGORY_MAP["purview"] == Category.COMPLIANCE
        assert CATEGORY_MAP["fabric"] == Category.DATA_PROTECTION


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
        # Per-user MFA controls use CIS Azure v2.1 Section 1.1 numbers.
        # Monkey365 rule metadata cites CIS Azure v3.0 refs 2.1.2/2.1.3, but
        # those collide with Prowler's Defender plan checks (v2.1 numbering).
        assert DEDUP_KEY_RULES["aad_privileged_users_with_mfa_disabled"] == "cis:azure:1.1.2"
        assert DEDUP_KEY_RULES["aad_users_with_mfa_disabled"] == "cis:azure:1.1.3"

    def test_keys_are_monkey365_idsuffix_format(self) -> None:
        """Monkey365 idSuffix values use underscore-separated lowercase."""
        for key in DEDUP_KEY_RULES:
            assert key == key.lower(), f"Dedup key {key} must be lowercase"
            assert "." not in key, f"Dedup key {key} must not contain dots (use underscores)"
