"""Tests for Maester declarative mappings -- data completeness and consistency."""

import json
from pathlib import Path
from typing import Any

import pytest

from gxassessms.adapters.maester.mappings import (
    BLOCK_CATEGORY_MAP,
    DEDUP_KEY_RULES,
    SEVERITY_MAP,
)
from gxassessms.core.domain.enums import Category, Severity


@pytest.fixture
def fixture_data() -> list[dict[str, Any]]:
    """Load the Maester fixture data."""
    fixture_path = (
        Path(__file__).parent.parent.parent.parent
        / "src"
        / "gxassessms"
        / "adapters"
        / "maester"
        / "fixtures"
        / "MaesterTestResults.json"
    )
    with open(fixture_path) as f:
        data = json.load(f)
    return data["Tests"]


class TestSeverityMap:
    def test_severity_map_is_dict(self) -> None:
        assert isinstance(SEVERITY_MAP, dict)

    def test_severity_map_keys_are_strings(self) -> None:
        for key in SEVERITY_MAP:
            assert isinstance(key, str)

    def test_severity_map_values_are_valid_severities(self) -> None:
        for severity in SEVERITY_MAP.values():
            assert isinstance(severity, Severity)

    def test_critical_maps_to_critical(self) -> None:
        assert SEVERITY_MAP["Critical"] == Severity.CRITICAL

    def test_high_maps_to_high(self) -> None:
        assert SEVERITY_MAP["High"] == Severity.HIGH

    def test_medium_maps_to_medium(self) -> None:
        assert SEVERITY_MAP["Medium"] == Severity.MEDIUM

    def test_low_maps_to_low(self) -> None:
        assert SEVERITY_MAP["Low"] == Severity.LOW

    def test_info_maps_to_info(self) -> None:
        """Maester uses 'Info', not 'Informational'."""
        assert SEVERITY_MAP["Info"] == Severity.INFO

    def test_empty_string_maps_to_info(self) -> None:
        """Empty severity string (occurs in real data) defaults to INFO."""
        assert SEVERITY_MAP[""] == Severity.INFO

    def test_fixture_severities_covered(self, fixture_data: list[dict[str, Any]]) -> None:
        """Every Severity value in fixtures is in SEVERITY_MAP."""
        unmapped_severities: set[str] = set()
        for test in fixture_data:
            severity = test["Severity"]
            if severity not in SEVERITY_MAP:
                unmapped_severities.add(severity)
        assert unmapped_severities == set(), (
            f"Unmapped severity values in fixtures: {unmapped_severities}"
        )


class TestBlockCategoryMap:
    """Category mapping uses Maester's Block field, not a Category field."""

    def test_block_category_map_is_dict(self) -> None:
        assert isinstance(BLOCK_CATEGORY_MAP, dict)

    def test_block_category_map_keys_are_strings(self) -> None:
        for key in BLOCK_CATEGORY_MAP:
            assert isinstance(key, str)

    def test_block_category_map_values_are_valid_categories(self) -> None:
        for category in BLOCK_CATEGORY_MAP.values():
            assert isinstance(category, Category)

    def test_cis_maps_to_compliance(self) -> None:
        assert BLOCK_CATEGORY_MAP["CIS"] == Category.COMPLIANCE

    def test_cisa_maps_to_compliance(self) -> None:
        assert BLOCK_CATEGORY_MAP["CISA"] == Category.COMPLIANCE

    def test_eidsca_maps_to_identity_access(self) -> None:
        assert BLOCK_CATEGORY_MAP["EIDSCA"] == Category.IDENTITY_ACCESS

    def test_maester_entra_maps_to_identity_access(self) -> None:
        assert BLOCK_CATEGORY_MAP["Maester/Entra"] == Category.IDENTITY_ACCESS

    def test_orca_maps_to_email_collaboration(self) -> None:
        assert BLOCK_CATEGORY_MAP["ORCA"] == Category.EMAIL_COLLABORATION

    def test_maester_exchange_maps_to_email_collaboration(self) -> None:
        assert BLOCK_CATEGORY_MAP["Maester/Exchange"] == Category.EMAIL_COLLABORATION

    def test_maester_teams_maps_to_email_collaboration(self) -> None:
        assert BLOCK_CATEGORY_MAP["Maester/Teams"] == Category.EMAIL_COLLABORATION

    def test_maester_intune_maps_to_device_management(self) -> None:
        assert BLOCK_CATEGORY_MAP["Maester/Intune"] == Category.DEVICE_MANAGEMENT

    def test_fixture_blocks_covered(self, fixture_data: list[dict[str, Any]]) -> None:
        """Every Block value in fixtures has a matching category map entry."""
        unmapped_blocks: set[str] = set()
        for test in fixture_data:
            block = test.get("Block", "")
            if block and block not in BLOCK_CATEGORY_MAP:
                unmapped_blocks.add(block)
        assert unmapped_blocks == set(), f"Unmapped Block values in fixtures: {unmapped_blocks}"


class TestDedupKeyRules:
    def test_dedup_key_rules_is_dict(self) -> None:
        assert isinstance(DEDUP_KEY_RULES, dict)

    def test_dedup_key_values_are_namespaced(self) -> None:
        for key, value in DEDUP_KEY_RULES.items():
            assert ":" in value, f"Dedup key for {key} must be namespaced (contain ':')"

    def test_cisa_scuba_mappings_present(self) -> None:
        """CISA tests overlap with ScubaGear -- must map to same dedup keys."""
        assert DEDUP_KEY_RULES["CISA.MS.AAD.3.1"] == "cis:m365:1.1.1"
        assert DEDUP_KEY_RULES["CISA.MS.EXO.4.1"] == "cis:m365:2.1.1"

    def test_cis_benchmark_mappings_present(self) -> None:
        """CIS M365 benchmark tests map to cis: namespace directly."""
        assert DEDUP_KEY_RULES["CIS.M365.1.1.1"] == "cis:m365:1.1.1:cloud_only_admins"

    def test_keys_are_valid_maester_test_ids(self) -> None:
        """Maester test IDs use multiple prefixes, not just MT."""
        valid_prefixes = ("MT.", "CIS.M365.", "CISA.MS.", "EIDSCA.", "ORCA.")
        for key in DEDUP_KEY_RULES:
            assert any(key.startswith(p) for p in valid_prefixes), (
                f"Dedup key {key} must start with a known Maester ID prefix"
            )
