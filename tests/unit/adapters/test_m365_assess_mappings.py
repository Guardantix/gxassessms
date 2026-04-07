"""Tests for M365-Assess declarative mappings."""

from gxassessms.adapters.m365_assess.mappings import (
    CATEGORY_MAP,
    DEDUP_KEY_RULES,
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

    def test_entapp_prefix(self) -> None:
        assert CATEGORY_MAP["entapp"] == Category.IDENTITY_ACCESS

    def test_dns_prefix(self) -> None:
        assert CATEGORY_MAP["dns"] == Category.EMAIL_COLLABORATION

    def test_intune_prefix(self) -> None:
        assert CATEGORY_MAP["intune"] == Category.DEVICE_MANAGEMENT

    def test_purview_prefix(self) -> None:
        assert CATEGORY_MAP["purview"] == Category.COMPLIANCE

    def test_powerbi_prefix(self) -> None:
        assert CATEGORY_MAP["powerbi"] == Category.DATA_PROTECTION

    def test_forms_prefix(self) -> None:
        assert CATEGORY_MAP["forms"] == Category.EMAIL_COLLABORATION


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


class TestDedupKeyRules:
    """Verify cross-tool dedup mappings resolve to canonical CIS control IDs.

    Keys use full subcheck IDs (with .N suffix) as emitted by SecurityConfigHelper.ps1.
    """

    def test_entra_cloudadmin_maps_to_cis_1_1_1(self) -> None:
        assert DEDUP_KEY_RULES["ENTRA-CLOUDADMIN-001.1"] == "cis:m365:1.1.1"

    def test_entra_admin_maps_to_cis_1_1_3(self) -> None:
        assert DEDUP_KEY_RULES["ENTRA-ADMIN-001.1"] == "cis:m365:1.1.3"

    def test_ca_mfa_admin_maps_to_cis_5_2_2_1(self) -> None:
        assert DEDUP_KEY_RULES["CA-MFA-ADMIN-001.1"] == "cis:m365:5.2.2.1"

    def test_ca_mfa_all_maps_to_cis_5_2_2_2(self) -> None:
        assert DEDUP_KEY_RULES["CA-MFA-ALL-001.1"] == "cis:m365:5.2.2.2"

    def test_all_values_use_cis_namespace(self) -> None:
        for key, value in DEDUP_KEY_RULES.items():
            assert value.startswith("cis:m365:"), (
                f"DEDUP_KEY_RULES[{key!r}] = {value!r} -- expected 'cis:m365:' namespace"
            )

    def test_all_keys_have_subcheck_suffix(self) -> None:
        """All keys must include the .N suffix since SecurityConfigHelper always appends it."""
        import re

        pattern = re.compile(r"\.\d+$")
        for key in DEDUP_KEY_RULES:
            assert pattern.search(key), (
                f"DEDUP_KEY_RULES key {key!r} missing .N suffix -- "
                "SecurityConfigHelper.ps1 always appends sub-numbering to CheckIds"
            )
