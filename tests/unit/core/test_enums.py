"""Tests for core domain enums."""

from gxassessms.core.domain.constants import SEVERITIES
from gxassessms.core.domain.enums import (
    Category,
    FindingStatus,
    Severity,
    ToolSource,
)


class TestSeverity:
    def test_all_values_match_constants(self) -> None:
        enum_values = {s.value for s in Severity}
        assert enum_values == SEVERITIES

    def test_is_str_enum(self) -> None:
        assert isinstance(Severity.CRITICAL, str)
        assert Severity.CRITICAL == "CRITICAL"

    def test_ordering_by_value(self) -> None:
        from gxassessms.core.domain.constants import SEVERITY_ORDER

        ordered = sorted(Severity, key=lambda s: SEVERITY_ORDER[s.value])
        assert [s.value for s in ordered] == ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class TestFindingStatus:
    def test_all_expected_statuses_exist(self) -> None:
        expected = {"FAIL", "PASS", "WARNING", "ERROR", "N/A", "MANUAL"}
        assert {s.value for s in FindingStatus} == expected

    def test_is_str_enum(self) -> None:
        assert isinstance(FindingStatus.FAIL, str)


class TestCategory:
    def test_all_expected_categories_exist(self) -> None:
        expected = {
            "Identity & Access",
            "Data Protection",
            "Device Management",
            "Email & Collaboration",
            "Infrastructure Security",
            "Network Security",
            "Logging & Monitoring",
            "Cost Optimization",
            "Operational Excellence",
            "Compliance & Governance",
            "Application Security",
        }
        assert {c.value for c in Category} == expected

    def test_is_str_enum(self) -> None:
        assert isinstance(Category.IDENTITY_ACCESS, str)


class TestToolSource:
    def test_has_manual_source(self) -> None:
        assert ToolSource.MANUAL.value == "Manual"

    def test_implemented_adapters_are_subset(self) -> None:
        implemented = {
            ToolSource.SCUBAGEAR,
            ToolSource.MAESTER,
            ToolSource.MONKEY365,
            ToolSource.M365_ASSESS,
            ToolSource.PROWLER,
            ToolSource.SECURE_SCORE,
            ToolSource.AZURE_ADVISOR,
        }
        assert implemented.issubset(set(ToolSource))

    def test_is_str_enum(self) -> None:
        assert isinstance(ToolSource.SCUBAGEAR, str)
