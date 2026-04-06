"""Tests for core domain constants (AD-79 pattern: Literal + frozenset)."""

from gxassessms.core.domain.constants import (
    ADAPTER_CAPABILITIES,
    ADAPTER_PLACEHOLDERS,
    CATEGORY_DISPLAY_NAMES,
    CONFIDENCE_LABELS,
    REMEDIATION_PHASE_TIMELINES,
    REMEDIATION_PHASES,
    SEVERITIES,
    SEVERITY_COLORS,
    SEVERITY_ORDER,
)


class TestSeverityConstants:
    def test_severity_order_covers_all_severities(self) -> None:
        assert set(SEVERITY_ORDER.keys()) == SEVERITIES

    def test_severity_order_is_ascending(self) -> None:
        values = list(SEVERITY_ORDER.values())
        assert values == sorted(values)

    def test_severity_colors_cover_all_severities(self) -> None:
        assert set(SEVERITY_COLORS.keys()) == SEVERITIES

    def test_severities_is_frozenset(self) -> None:
        assert isinstance(SEVERITIES, frozenset)

    def test_critical_is_highest_severity(self) -> None:
        max_sev = max(SEVERITY_ORDER, key=SEVERITY_ORDER.get)
        assert max_sev == "CRITICAL"


class TestRemediationPhaseConstants:
    def test_phases_is_frozenset(self) -> None:
        assert isinstance(REMEDIATION_PHASES, frozenset)

    def test_timelines_cover_all_phases(self) -> None:
        assert set(REMEDIATION_PHASE_TIMELINES.keys()) == REMEDIATION_PHASES


class TestCategoryConstants:
    def test_display_names_values_are_strings(self) -> None:
        for name in CATEGORY_DISPLAY_NAMES.values():
            assert isinstance(name, str)
            assert len(name) > 0


class TestConfidenceConstants:
    def test_labels_is_frozenset(self) -> None:
        assert isinstance(CONFIDENCE_LABELS, frozenset)


class TestAdapterCapabilities:
    def test_capabilities_is_frozenset(self) -> None:
        assert isinstance(ADAPTER_CAPABILITIES, frozenset)

    def test_placeholders_is_frozenset(self) -> None:
        assert isinstance(ADAPTER_PLACEHOLDERS, frozenset)

    def test_placeholders_are_disjoint_from_capabilities(self) -> None:
        # Placeholders are ToolSource values, capabilities are capability strings
        # They should not overlap
        assert ADAPTER_PLACEHOLDERS.isdisjoint(ADAPTER_CAPABILITIES)


class TestManifestConstants:
    def test_manifest_version_current_is_string(self) -> None:
        from gxassessms.core.domain.constants import MANIFEST_VERSION_CURRENT

        assert isinstance(MANIFEST_VERSION_CURRENT, str)
        assert MANIFEST_VERSION_CURRENT == "1.0.0"

    def test_tool_slug_pattern_matches_valid(self) -> None:
        import re

        from gxassessms.core.domain.constants import TOOL_SLUG_PATTERN

        assert re.fullmatch(TOOL_SLUG_PATTERN, "scubagear")
        assert re.fullmatch(TOOL_SLUG_PATTERN, "scubagear-v2")
        assert re.fullmatch(TOOL_SLUG_PATTERN, "a")

    def test_tool_slug_pattern_rejects_invalid(self) -> None:
        import re

        from gxassessms.core.domain.constants import TOOL_SLUG_PATTERN

        assert not re.fullmatch(TOOL_SLUG_PATTERN, "-scubagear")
        assert not re.fullmatch(TOOL_SLUG_PATTERN, "ScubaGear")
        assert not re.fullmatch(TOOL_SLUG_PATTERN, "scuba gear")
        assert not re.fullmatch(TOOL_SLUG_PATTERN, "")

    def test_encoding_by_extension_has_json(self) -> None:
        from gxassessms.core.domain.constants import ENCODING_BY_EXTENSION

        assert ENCODING_BY_EXTENSION[".json"] == "utf-8"

    def test_encoding_by_extension_default_is_binary(self) -> None:
        from gxassessms.core.domain.constants import ENCODING_BY_EXTENSION

        # Unknown extensions aren't in the dict; callers default to "binary"
        assert ".xyz" not in ENCODING_BY_EXTENSION

    def test_execution_metadata_allowlist_keys(self) -> None:
        from gxassessms.core.domain.constants import EXECUTION_METADATA_ALLOWLIST

        assert "1.0.0" in EXECUTION_METADATA_ALLOWLIST
        assert EXECUTION_METADATA_ALLOWLIST["1.0.0"]["scubagear"] == frozenset(
            {"modules", "module_provenance"}
        )
        assert EXECUTION_METADATA_ALLOWLIST["1.0.0"]["maester"] == frozenset({"module_provenance"})

    def test_execution_metadata_allowlist_has_all_adapters(self) -> None:
        from gxassessms.core.domain.constants import EXECUTION_METADATA_ALLOWLIST

        expected_slugs = {
            "scubagear",
            "maester",
            "monkey365",
            "m365-assess",
            "prowler",
            "azure-advisor",
            "secure-score",
        }
        assert set(EXECUTION_METADATA_ALLOWLIST["1.0.0"].keys()) == expected_slugs

    def test_recognized_manifest_versions(self) -> None:
        from gxassessms.core.domain.constants import RECOGNIZED_MANIFEST_VERSIONS

        assert "1.0.0" in RECOGNIZED_MANIFEST_VERSIONS


class TestSeverityIdentityMap:
    def test_covers_all_severity_x_non_passing_status_combos(self) -> None:
        from gxassessms.core.domain.constants import SEVERITY_IDENTITY_MAP
        from gxassessms.core.domain.enums import FindingStatus, Severity

        non_passing = {
            FindingStatus.FAIL,
            FindingStatus.WARNING,
            FindingStatus.ERROR,
            FindingStatus.MANUAL,
        }
        for sev in Severity:
            for status in non_passing:
                assert (sev, status) in SEVERITY_IDENTITY_MAP

    def test_identity_property(self) -> None:
        from gxassessms.core.domain.constants import SEVERITY_IDENTITY_MAP

        for (severity, _status), mapped in SEVERITY_IDENTITY_MAP.items():
            assert mapped == severity

    def test_pass_not_in_map(self) -> None:
        from gxassessms.core.domain.constants import SEVERITY_IDENTITY_MAP
        from gxassessms.core.domain.enums import FindingStatus, Severity

        for sev in Severity:
            assert (sev, FindingStatus.PASS) not in SEVERITY_IDENTITY_MAP

    def test_not_applicable_not_in_map(self) -> None:
        from gxassessms.core.domain.constants import SEVERITY_IDENTITY_MAP
        from gxassessms.core.domain.enums import FindingStatus, Severity

        for sev in Severity:
            assert (sev, FindingStatus.NOT_APPLICABLE) not in SEVERITY_IDENTITY_MAP
