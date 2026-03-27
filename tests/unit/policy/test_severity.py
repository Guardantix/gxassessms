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
