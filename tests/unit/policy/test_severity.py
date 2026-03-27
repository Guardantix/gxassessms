"""Tests for SeverityPolicy -- override suggestions and confidence-based adjustment."""

import pytest

from gxassessms.core.domain.enums import (
    Category,
    FindingStatus,
    Severity,
    ToolSource,
)
from gxassessms.core.domain.models import (
    ConfidenceScore,
    ConsolidatedFinding,
    SourceEvidence,
)
from gxassessms.policy.severity import (
    DefaultSeverityPolicy,
    SeverityPolicy,
)


@pytest.fixture
def sample_rules() -> dict:
    return {
        "escalation_thresholds": {
            "CRITICAL": 0.7,
            "HIGH": 0.5,
            "MEDIUM": 0.3,
            "LOW": 0.0,
            "INFO": 0.0,
        },
        "override_suggestions": {
            "suggestion_threshold": 3,
        },
        "confidence_adjustments": {
            "downgrade_threshold": 0.3,
            "upgrade_threshold": 0.9,
            "minimum_severity": "LOW",
            "maximum_severity": "CRITICAL",
        },
        "downgrade_map": {
            "CRITICAL": "HIGH",
            "HIGH": "MEDIUM",
            "MEDIUM": "LOW",
            "LOW": "INFO",
            "INFO": "INFO",
        },
        "upgrade_map": {
            "INFO": "LOW",
            "LOW": "MEDIUM",
            "MEDIUM": "HIGH",
            "HIGH": "CRITICAL",
            "CRITICAL": "CRITICAL",
        },
    }


def _make_consolidated(
    *,
    severity: Severity = Severity.CRITICAL,
    confidence_overall: float = 0.88,
    finding_key: str = "cis:m365:1.1.1",
) -> ConsolidatedFinding:
    return ConsolidatedFinding(
        finding_instance_id="uuid-001",
        finding_key=finding_key,
        title="Test finding",
        severity=severity,
        status=FindingStatus.FAIL,
        category=Category.IDENTITY_ACCESS,
        description="Test",
        sources=[
            SourceEvidence(
                tool=ToolSource.SCUBAGEAR,
                check_id="MS.AAD.3.1v1",
                raw_data={},
            )
        ],
        confidence=ConfidenceScore(
            evidence_strength=0.8,
            corroborating_tools=1,
            data_freshness=1.0,
            provenance="system-generated",
            overall=confidence_overall,
        ),
    )


class TestSeverityProtocol:
    def test_default_policy_satisfies_protocol(self, sample_rules: dict) -> None:
        policy = DefaultSeverityPolicy(rules=sample_rules)
        assert isinstance(policy, SeverityPolicy)


class TestConfidenceBasedAdjustment:
    def test_no_adjustment_when_confidence_sufficient(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.CRITICAL, confidence_overall=0.88)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        adjustments = policy.suggest_adjustments(findings=[cf])
        # Confidence 0.88 >= CRITICAL threshold 0.7 -> no downgrade
        assert len(adjustments) == 0

    def test_downgrade_when_confidence_below_threshold(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.CRITICAL, confidence_overall=0.5)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        adjustments = policy.suggest_adjustments(findings=[cf])
        assert len(adjustments) == 1
        adj = adjustments[0]
        assert adj.finding_instance_id == "uuid-001"
        assert adj.current_severity == Severity.CRITICAL
        assert adj.suggested_severity == Severity.HIGH
        assert "confidence" in adj.reason.lower()

    def test_no_downgrade_below_minimum(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.LOW, confidence_overall=0.1)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        adjustments = policy.suggest_adjustments(findings=[cf])
        # LOW threshold is 0.0, so confidence 0.1 >= 0.0 -> no downgrade
        assert len(adjustments) == 0

    def test_downgrade_medium_below_threshold(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.MEDIUM, confidence_overall=0.2)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        adjustments = policy.suggest_adjustments(findings=[cf])
        assert len(adjustments) == 1
        assert adjustments[0].suggested_severity == Severity.LOW

    def test_multiple_findings_processed(self, sample_rules: dict) -> None:
        cf1 = _make_consolidated(
            severity=Severity.CRITICAL,
            confidence_overall=0.4,
            finding_key="cis:m365:1.1.1",
        )
        cf2 = _make_consolidated(
            severity=Severity.HIGH,
            confidence_overall=0.3,
            finding_key="cis:m365:2.1.1",
        )
        # Override instance IDs to be unique
        cf2 = cf2.model_copy(update={"finding_instance_id": "uuid-002"})

        policy = DefaultSeverityPolicy(rules=sample_rules)
        adjustments = policy.suggest_adjustments(findings=[cf1, cf2])
        assert len(adjustments) == 2


class TestEscalationCheck:
    def test_check_escalation_when_below_floor(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.HIGH, confidence_overall=0.3)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        result = policy.check_escalation(cf)
        assert result is True

    def test_no_escalation_when_above_floor(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.HIGH, confidence_overall=0.8)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        result = policy.check_escalation(cf)
        assert result is False

    def test_escalation_triggered_by_global_downgrade_threshold(self, sample_rules: dict) -> None:
        """check_escalation must apply the global downgrade floor, not just per-severity."""
        # HIGH escalation_threshold = 0.5; downgrade_threshold = 0.3
        # HIGH at 0.80: 0.80 >= max(0.5, 0.3) -> False (no escalation)
        # But if we set downgrade_threshold = 0.9, then:
        # HIGH at 0.80: 0.80 < max(0.5, 0.9) = 0.9 -> True (escalation triggered)
        rules = {
            **sample_rules,
            "confidence_adjustments": {
                **sample_rules["confidence_adjustments"],
                "downgrade_threshold": 0.9,
            },
        }
        cf = _make_consolidated(severity=Severity.HIGH, confidence_overall=0.80)
        policy = DefaultSeverityPolicy(rules=rules)
        assert policy.check_escalation(cf) is True

    def test_no_escalation_when_above_both_thresholds(self, sample_rules: dict) -> None:
        """check_escalation returns False when above the stricter of both thresholds."""
        # HIGH = 0.5; downgrade_threshold = 0.3; 0.80 >= max(0.5, 0.3) -> False
        cf = _make_consolidated(severity=Severity.HIGH, confidence_overall=0.80)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        assert policy.check_escalation(cf) is False


class TestOverrideSuggestions:
    def test_suggest_rule_change_above_threshold(self, sample_rules: dict) -> None:
        policy = DefaultSeverityPolicy(rules=sample_rules)
        override_history = {
            "cis:m365:1.1.1": {
                "from": "CRITICAL",
                "to": "HIGH",
                "count": 5,
            },
        }
        suggestions = policy.suggest_rule_changes(override_history)
        assert len(suggestions) == 1
        assert suggestions[0]["finding_key"] == "cis:m365:1.1.1"

    def test_no_suggestion_below_threshold(self, sample_rules: dict) -> None:
        policy = DefaultSeverityPolicy(rules=sample_rules)
        override_history = {
            "cis:m365:1.1.1": {
                "from": "CRITICAL",
                "to": "HIGH",
                "count": 1,
            },
        }
        suggestions = policy.suggest_rule_changes(override_history)
        assert len(suggestions) == 0

    def test_empty_history_no_suggestions(self, sample_rules: dict) -> None:
        policy = DefaultSeverityPolicy(rules=sample_rules)
        suggestions = policy.suggest_rule_changes({})
        assert len(suggestions) == 0


class TestMinimumSeverityFloor:
    def test_downgrade_blocked_by_minimum_severity(self, sample_rules: dict) -> None:
        # Set LOW threshold > 0 so LOW findings qualify for downgrade,
        # but minimum_severity = "LOW" should block LOW -> INFO.
        rules = {
            **sample_rules,
            "escalation_thresholds": {**sample_rules["escalation_thresholds"], "LOW": 0.9},
            "confidence_adjustments": {"minimum_severity": "LOW"},
        }
        cf = _make_consolidated(severity=Severity.LOW, confidence_overall=0.1)
        policy = DefaultSeverityPolicy(rules=rules)
        adjustments = policy.suggest_adjustments(findings=[cf])
        assert len(adjustments) == 0

    def test_downgrade_allowed_above_minimum_severity(self, sample_rules: dict) -> None:
        # MEDIUM can still downgrade to LOW when minimum_severity = "LOW".
        cf = _make_consolidated(severity=Severity.MEDIUM, confidence_overall=0.2)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        adjustments = policy.suggest_adjustments(findings=[cf])
        assert len(adjustments) == 1
        assert adjustments[0].suggested_severity == Severity.LOW


class TestUpgradeAdjustments:
    def test_upgrade_when_confidence_above_threshold(self, sample_rules: dict) -> None:
        # LOW with confidence 0.95 >= upgrade_threshold 0.9 -> suggest MEDIUM
        cf = _make_consolidated(severity=Severity.LOW, confidence_overall=0.95)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        adjustments = policy.suggest_adjustments(findings=[cf])
        assert len(adjustments) == 1
        assert adjustments[0].suggested_severity == Severity.MEDIUM
        assert "upgrade threshold" in adjustments[0].reason

    def test_no_upgrade_when_confidence_below_threshold(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.LOW, confidence_overall=0.5)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        adjustments = policy.suggest_adjustments(findings=[cf])
        assert len(adjustments) == 0

    def test_upgrade_blocked_by_maximum_severity(self, sample_rules: dict) -> None:
        # CRITICAL cannot upgrade further; upgrade_map has CRITICAL -> CRITICAL
        cf = _make_consolidated(severity=Severity.CRITICAL, confidence_overall=0.95)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        adjustments = policy.suggest_adjustments(findings=[cf])
        assert len(adjustments) == 0

    def test_upgrade_blocked_by_configured_maximum(self, sample_rules: dict) -> None:
        # Set maximum_severity = "MEDIUM"; HIGH at 0.95 confidence is blocked.
        rules = {
            **sample_rules,
            "confidence_adjustments": {
                **sample_rules["confidence_adjustments"],
                "maximum_severity": "MEDIUM",
            },
        }
        cf = _make_consolidated(severity=Severity.HIGH, confidence_overall=0.95)
        policy = DefaultSeverityPolicy(rules=rules)
        adjustments = policy.suggest_adjustments(findings=[cf])
        assert len(adjustments) == 0

    def test_no_upgrade_without_upgrade_threshold_configured(self, sample_rules: dict) -> None:
        rules = {**sample_rules, "confidence_adjustments": {}}
        cf = _make_consolidated(severity=Severity.LOW, confidence_overall=1.0)
        policy = DefaultSeverityPolicy(rules=rules)
        adjustments = policy.suggest_adjustments(findings=[cf])
        assert len(adjustments) == 0


class TestDowngradeThreshold:
    def test_global_downgrade_threshold_overrides_permissive_per_severity(
        self, sample_rules: dict
    ) -> None:
        # escalation_thresholds.HIGH = 0.5; with downgrade_threshold=0.9,
        # HIGH at 0.80 confidence should now trigger a downgrade suggestion.
        rules = {
            **sample_rules,
            "confidence_adjustments": {
                **sample_rules["confidence_adjustments"],
                "downgrade_threshold": 0.9,
            },
        }
        cf = _make_consolidated(severity=Severity.HIGH, confidence_overall=0.80)
        policy = DefaultSeverityPolicy(rules=rules)
        adjustments = policy.suggest_adjustments(findings=[cf])
        assert len(adjustments) == 1
        assert adjustments[0].suggested_severity == Severity.MEDIUM

    def test_per_severity_threshold_still_used_when_stricter(self, sample_rules: dict) -> None:
        # escalation_thresholds.CRITICAL = 0.7; downgrade_threshold=0.3.
        # CRITICAL at 0.6 confidence is below 0.7 -> still triggers downgrade.
        cf = _make_consolidated(severity=Severity.CRITICAL, confidence_overall=0.6)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        adjustments = policy.suggest_adjustments(findings=[cf])
        assert len(adjustments) == 1
        assert adjustments[0].suggested_severity == Severity.HIGH


class TestPassNotApplicableExclusion:
    def test_no_upgrade_for_pass_finding(self, sample_rules: dict) -> None:
        """PASS findings must never receive upgrade suggestions regardless of confidence."""
        # INFO severity, confidence 0.95 >= upgrade_threshold 0.9 -- would normally upgrade to LOW.
        cf = _make_consolidated(severity=Severity.INFO, confidence_overall=0.95)
        cf = cf.model_copy(update={"status": FindingStatus.PASS})
        policy = DefaultSeverityPolicy(rules=sample_rules)
        assert policy.suggest_adjustments([cf]) == []

    def test_no_upgrade_for_not_applicable_finding(self, sample_rules: dict) -> None:
        """NOT_APPLICABLE findings must never receive upgrade suggestions."""
        cf = _make_consolidated(severity=Severity.INFO, confidence_overall=0.95)
        cf = cf.model_copy(update={"status": FindingStatus.NOT_APPLICABLE})
        policy = DefaultSeverityPolicy(rules=sample_rules)
        assert policy.suggest_adjustments([cf]) == []

    def test_no_downgrade_for_pass_finding(self, sample_rules: dict) -> None:
        """PASS findings must never receive downgrade suggestions regardless of confidence."""
        cf = _make_consolidated(severity=Severity.INFO, confidence_overall=0.0)
        cf = cf.model_copy(update={"status": FindingStatus.PASS})
        policy = DefaultSeverityPolicy(rules=sample_rules)
        assert policy.suggest_adjustments([cf]) == []


class TestCheckEscalationMinimumSeverityFloor:
    def test_no_escalation_when_downgrade_below_minimum_severity(self, sample_rules: dict) -> None:
        """check_escalation must return False when downgrade target is below minimum_severity.

        sample_rules has minimum_severity=LOW. LOW -> INFO (order 0) < LOW (order 1).
        Confidence 0.25 < effective_threshold 0.3, but no actionable downgrade -> False.
        """
        cf = _make_consolidated(severity=Severity.LOW, confidence_overall=0.25)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        assert policy.check_escalation(cf) is False

    def test_no_escalation_at_downgrade_map_floor(self, sample_rules: dict) -> None:
        """check_escalation must return False when downgrade_map returns the same severity."""
        # INFO -> INFO in downgrade_map; no actionable downgrade possible.
        cf = _make_consolidated(severity=Severity.INFO, confidence_overall=0.0)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        assert policy.check_escalation(cf) is False

    def test_escalation_actionable_above_minimum_severity(self, sample_rules: dict) -> None:
        """check_escalation returns True when downgrade is both possible and above the floor."""
        # MEDIUM -> LOW (order 1) >= minimum_severity=LOW (order 1). Confidence 0.25 < 0.3.
        cf = _make_consolidated(severity=Severity.MEDIUM, confidence_overall=0.25)
        policy = DefaultSeverityPolicy(rules=sample_rules)
        assert policy.check_escalation(cf) is True

    def test_no_escalation_for_pass_with_non_info_severity(self, sample_rules: dict) -> None:
        """PASS findings must return False from check_escalation even when severity is non-INFO.

        Persisted or manually edited data can produce status=PASS with a non-INFO severity.
        check_escalation() must mirror suggest_adjustments() and treat these as non-actionable.
        """
        # HIGH severity + PASS status: simulates a persisted/edited finding
        cf = _make_consolidated(severity=Severity.HIGH, confidence_overall=0.1)
        cf = cf.model_copy(update={"status": FindingStatus.PASS})
        policy = DefaultSeverityPolicy(rules=sample_rules)
        assert policy.check_escalation(cf) is False

    def test_no_escalation_for_not_applicable_with_non_info_severity(
        self, sample_rules: dict
    ) -> None:
        """NOT_APPLICABLE findings must return False from check_escalation."""
        cf = _make_consolidated(severity=Severity.HIGH, confidence_overall=0.1)
        cf = cf.model_copy(update={"status": FindingStatus.NOT_APPLICABLE})
        policy = DefaultSeverityPolicy(rules=sample_rules)
        assert policy.check_escalation(cf) is False
