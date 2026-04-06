"""Tests for Maester declarative mappings -- data completeness and consistency."""

import json
from pathlib import Path
from typing import Any

import pytest

from gxassessms.adapters.maester.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
    SEVERITY_MAP,
)
from gxassessms.core.domain.enums import Category, FindingStatus, Severity


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

    def test_severity_map_keys_are_tuples(self) -> None:
        """Keys are (native_severity, canonicalized_status) tuples."""
        for key in SEVERITY_MAP:
            assert isinstance(key, tuple)
            assert len(key) == 2

    def test_severity_map_values_are_valid_severities(self) -> None:
        for severity in SEVERITY_MAP.values():
            assert isinstance(severity, Severity)

    def test_critical_fail_maps_to_critical(self) -> None:
        assert SEVERITY_MAP[("Critical", FindingStatus.FAIL)] == Severity.CRITICAL

    def test_high_fail_maps_to_high(self) -> None:
        assert SEVERITY_MAP[("High", FindingStatus.FAIL)] == Severity.HIGH

    def test_medium_fail_maps_to_medium(self) -> None:
        assert SEVERITY_MAP[("Medium", FindingStatus.FAIL)] == Severity.MEDIUM

    def test_low_fail_maps_to_low(self) -> None:
        assert SEVERITY_MAP[("Low", FindingStatus.FAIL)] == Severity.LOW

    def test_info_fail_maps_to_low(self) -> None:
        """Info-severity failure is still actionable, mapped to LOW."""
        assert SEVERITY_MAP[("Info", FindingStatus.FAIL)] == Severity.LOW

    def test_empty_severity_fail_maps_to_medium(self) -> None:
        """Empty severity string (occurs in real data) defaults to MEDIUM on failure."""
        assert SEVERITY_MAP[("", FindingStatus.FAIL)] == Severity.MEDIUM

    def test_fixture_severities_covered_for_fail(self, fixture_data: list[dict[str, Any]]) -> None:
        """Every Severity value in fixtures has a FAIL entry in SEVERITY_MAP."""
        unmapped_severities: set[str] = set()
        for test in fixture_data:
            severity = test["Severity"]
            if (severity, FindingStatus.FAIL) not in SEVERITY_MAP:
                unmapped_severities.add(severity)
        assert unmapped_severities == set(), (
            f"Unmapped severity values in fixtures (for FAIL status): {unmapped_severities}"
        )


class TestCategoryMap:
    """Category mapping uses check-ID prefix (lowercased), not Block field."""

    def test_category_map_is_dict(self) -> None:
        assert isinstance(CATEGORY_MAP, dict)

    def test_category_map_keys_are_lowercase_strings(self) -> None:
        for key in CATEGORY_MAP:
            assert isinstance(key, str)
            assert key == key.lower(), f"Category map key must be lowercase: {key!r}"

    def test_category_map_values_are_valid_categories(self) -> None:
        for category in CATEGORY_MAP.values():
            assert isinstance(category, Category)

    def test_cis_maps_to_compliance(self) -> None:
        assert CATEGORY_MAP["cis"] == Category.COMPLIANCE

    def test_cisa_maps_to_compliance(self) -> None:
        assert CATEGORY_MAP["cisa"] == Category.COMPLIANCE

    def test_eidsca_maps_to_identity_access(self) -> None:
        assert CATEGORY_MAP["eidsca"] == Category.IDENTITY_ACCESS

    def test_orca_maps_to_email_collaboration(self) -> None:
        assert CATEGORY_MAP["orca"] == Category.EMAIL_COLLABORATION

    def test_mt_maps_to_identity_access(self) -> None:
        assert CATEGORY_MAP["mt"] == Category.IDENTITY_ACCESS

    def test_fixture_id_prefixes_covered(self, fixture_data: list[dict[str, Any]]) -> None:
        """Every check-ID prefix in fixtures has a matching category map entry."""
        unmapped_prefixes: set[str] = set()
        for test in fixture_data:
            test_id = test["Id"]
            parts = test_id.split(".")
            if len(parts) >= 2:
                prefix = parts[0].lower()
                if prefix not in CATEGORY_MAP:
                    unmapped_prefixes.add(prefix)
        assert unmapped_prefixes == set(), (
            f"Unmapped check-ID prefixes in fixtures: {unmapped_prefixes}"
        )


class TestDedupKeyRules:
    def test_dedup_key_rules_is_dict(self) -> None:
        assert isinstance(DEDUP_KEY_RULES, dict)

    def test_dedup_key_values_are_namespaced(self) -> None:
        for key, value in DEDUP_KEY_RULES.items():
            assert ":" in value, f"Dedup key for {key} must be namespaced (contain ':')"

    def test_cisa_scuba_mappings_present(self) -> None:
        """CISA tests overlap with ScubaGear -- must map to same dedup keys."""
        assert DEDUP_KEY_RULES["CISA.MS.AAD.7.3"] == "cis:m365:1.1.1"
        assert DEDUP_KEY_RULES["CISA.MS.EXO.4.1"] == "cis:m365:2.1.10"

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
