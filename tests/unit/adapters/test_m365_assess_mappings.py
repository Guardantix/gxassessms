"""Tests for M365-Assess declarative mappings."""

from gxassessms.adapters.m365_assess.mappings import (
    CATEGORY_MAP,
    SEVERITY_MAP,
    STATUS_MAP,
    extract_base_check_id,
)
from gxassessms.core.domain.enums import Category, FindingStatus, Severity


class TestStatusMap:
    """Maps M365-Assess CSV Status -> domain FindingStatus."""

    def test_all_six_statuses_present(self) -> None:
        assert len(STATUS_MAP) == 6

    def test_pass(self) -> None:
        assert STATUS_MAP["Pass"] == FindingStatus.PASS

    def test_fail(self) -> None:
        assert STATUS_MAP["Fail"] == FindingStatus.FAIL

    def test_warning(self) -> None:
        assert STATUS_MAP["Warning"] == FindingStatus.WARNING

    def test_review(self) -> None:
        assert STATUS_MAP["Review"] == FindingStatus.MANUAL

    def test_info(self) -> None:
        assert STATUS_MAP["Info"] == FindingStatus.NOT_APPLICABLE

    def test_unknown(self) -> None:
        assert STATUS_MAP["Unknown"] == FindingStatus.ERROR


class TestSeverityMap:
    """Maps risk-severity.json severity string -> domain Severity."""

    def test_all_five_levels(self) -> None:
        assert SEVERITY_MAP["Critical"] == Severity.CRITICAL
        assert SEVERITY_MAP["High"] == Severity.HIGH
        assert SEVERITY_MAP["Medium"] == Severity.MEDIUM
        assert SEVERITY_MAP["Low"] == Severity.LOW
        assert SEVERITY_MAP["Info"] == Severity.INFO


class TestCategoryMap:
    """Maps CheckId collector prefix -> domain Category."""

    def test_entra_prefix(self) -> None:
        assert CATEGORY_MAP["ENTRA"] == Category.IDENTITY_ACCESS

    def test_ca_prefix(self) -> None:
        assert CATEGORY_MAP["CA"] == Category.IDENTITY_ACCESS

    def test_exo_prefix(self) -> None:
        assert CATEGORY_MAP["EXO"] == Category.EMAIL_COLLABORATION

    def test_defender_prefix(self) -> None:
        assert CATEGORY_MAP["DEFENDER"] == Category.EMAIL_COLLABORATION

    def test_spo_prefix(self) -> None:
        assert CATEGORY_MAP["SPO"] == Category.DATA_PROTECTION

    def test_teams_prefix(self) -> None:
        assert CATEGORY_MAP["TEAMS"] == Category.EMAIL_COLLABORATION

    def test_compliance_prefix(self) -> None:
        assert CATEGORY_MAP["COMPLIANCE"] == Category.COMPLIANCE


class TestExtractBaseCheckId:
    """Strip .N sub-numbering from CheckId."""

    def test_strips_sub_number(self) -> None:
        assert extract_base_check_id("ENTRA-ADMIN-001.1") == "ENTRA-ADMIN-001"

    def test_multi_digit_sub_number(self) -> None:
        assert extract_base_check_id("DEFENDER-ANTIPHISH-001.15") == "DEFENDER-ANTIPHISH-001"

    def test_no_sub_number(self) -> None:
        assert extract_base_check_id("ENTRA-ADMIN-001") == "ENTRA-ADMIN-001"

    def test_extracts_collector_prefix(self) -> None:
        assert extract_base_check_id("CA-MFA-ADMIN-001.1").split("-")[0] == "CA"
