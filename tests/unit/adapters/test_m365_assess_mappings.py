"""Tests for M365-Assess declarative mappings."""

from gxassessms.adapters.m365_assess.mappings import (
    CATEGORY_MAP,
    SEVERITY_MAP,
    STATUS_MAP,
    extract_base_check_id,
    extract_collector_prefix,
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
    """Maps (severity_string, canonical_status) -> domain Severity.

    The adapter severity_map uses tuple keys so DefaultNormalizationPolicy
    can look up (obs.native_severity, _mapped_status) directly.
    """

    def test_critical_fail(self) -> None:
        assert SEVERITY_MAP[("Critical", "FAIL")] == Severity.CRITICAL

    def test_high_fail(self) -> None:
        assert SEVERITY_MAP[("High", "FAIL")] == Severity.HIGH

    def test_high_warning(self) -> None:
        assert SEVERITY_MAP[("High", "WARNING")] == Severity.HIGH

    def test_medium_fail(self) -> None:
        assert SEVERITY_MAP[("Medium", "FAIL")] == Severity.MEDIUM

    def test_low_fail(self) -> None:
        assert SEVERITY_MAP[("Low", "FAIL")] == Severity.LOW

    def test_info_fail(self) -> None:
        assert SEVERITY_MAP[("Info", "FAIL")] == Severity.INFO

    def test_all_actionable_statuses_covered(self) -> None:
        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            for status in ("FAIL", "WARNING", "MANUAL", "ERROR"):
                assert (sev, status) in SEVERITY_MAP


class TestCategoryMap:
    """Maps CheckId collector prefix (lowercase) -> domain Category.

    Keys must be lowercase to match what _extract_module_prefix returns
    after applying lower() to the first hyphen-split segment.
    """

    def test_entra_prefix(self) -> None:
        assert CATEGORY_MAP["entra"] == Category.IDENTITY_ACCESS

    def test_ca_prefix(self) -> None:
        assert CATEGORY_MAP["ca"] == Category.IDENTITY_ACCESS

    def test_exo_prefix(self) -> None:
        assert CATEGORY_MAP["exo"] == Category.EMAIL_COLLABORATION

    def test_defender_prefix(self) -> None:
        assert CATEGORY_MAP["defender"] == Category.EMAIL_COLLABORATION

    def test_spo_prefix(self) -> None:
        assert CATEGORY_MAP["spo"] == Category.DATA_PROTECTION

    def test_teams_prefix(self) -> None:
        assert CATEGORY_MAP["teams"] == Category.EMAIL_COLLABORATION

    def test_compliance_prefix(self) -> None:
        assert CATEGORY_MAP["compliance"] == Category.COMPLIANCE


class TestExtractBaseCheckId:
    """Strip .N sub-numbering from CheckId."""

    def test_strips_sub_number(self) -> None:
        assert extract_base_check_id("ENTRA-ADMIN-001.1") == "ENTRA-ADMIN-001"

    def test_multi_digit_sub_number(self) -> None:
        assert extract_base_check_id("DEFENDER-ANTIPHISH-001.15") == "DEFENDER-ANTIPHISH-001"

    def test_no_sub_number(self) -> None:
        assert extract_base_check_id("ENTRA-ADMIN-001") == "ENTRA-ADMIN-001"

    def test_hyphenated_prefix_unchanged(self) -> None:
        assert extract_base_check_id("CA-MFA-ADMIN-001.1") == "CA-MFA-ADMIN-001"


class TestExtractCollectorPrefix:
    """Extract first hyphen-delimited segment from CheckId."""

    def test_simple_prefix(self) -> None:
        assert extract_collector_prefix("ENTRA-ADMIN-001.1") == "ENTRA"

    def test_two_char_prefix(self) -> None:
        assert extract_collector_prefix("CA-MFA-ADMIN-001.1") == "CA"

    def test_no_sub_number(self) -> None:
        assert extract_collector_prefix("EXO-AUTH-001") == "EXO"

    def test_multi_segment_prefix(self) -> None:
        assert extract_collector_prefix("DEFENDER-ANTIPHISH-001.15") == "DEFENDER"
