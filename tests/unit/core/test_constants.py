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
    AdapterCapability,
    ConfidenceLabel,
    RemediationPhase,
    SeverityLevel,
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
