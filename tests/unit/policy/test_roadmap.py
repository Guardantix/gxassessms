"""Tests for RoadmapPolicy -- phase assignment, priority scoring, timeline estimation."""

import logging

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
from gxassessms.policy.roadmap import (
    DefaultRoadmapPolicy,
    RoadmapPolicy,
)


@pytest.fixture
def sample_rules() -> dict:
    return {
        "phases": {
            "IMMEDIATE": {
                "timeline": "0-30 days",
                "description": "Critical security gaps",
            },
            "SHORT_TERM": {
                "timeline": "30-90 days",
                "description": "High-priority items",
            },
            "MEDIUM_TERM": {
                "timeline": "90-180 days",
                "description": "Medium-priority improvements",
            },
            "LONG_TERM": {
                "timeline": "180+ days",
                "description": "Strategic improvements",
            },
        },
        "severity_to_phase": {
            "CRITICAL": "IMMEDIATE",
            "HIGH": "SHORT_TERM",
            "MEDIUM": "MEDIUM_TERM",
            "LOW": "LONG_TERM",
            "INFO": "LONG_TERM",
        },
        "priority_weights": {
            "severity": 0.40,
            "confidence": 0.25,
            "category_weight": 0.20,
            "corroboration": 0.15,
        },
        "severity_scores": {
            "CRITICAL": 100,
            "HIGH": 75,
            "MEDIUM": 50,
            "LOW": 25,
            "INFO": 10,
        },
        "category_priority": {
            "IDENTITY_ACCESS": 1.3,
            "DATA_PROTECTION": 1.2,
            "COMPLIANCE": 1.0,
            "COST_OPTIMIZATION": 0.7,
        },
    }


def _make_consolidated(
    *,
    severity: Severity = Severity.CRITICAL,
    category: Category = Category.IDENTITY_ACCESS,
    confidence_overall: float = 0.88,
    corroborating_tools: int = 2,
    finding_key: str = "cis:m365:1.1.1",
    instance_id: str = "uuid-001",
) -> ConsolidatedFinding:
    return ConsolidatedFinding(
        finding_instance_id=instance_id,
        finding_key=finding_key,
        title="Test finding",
        severity=severity,
        status=FindingStatus.FAIL,
        category=category,
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
            corroborating_tools=corroborating_tools,
            data_freshness=1.0,
            provenance="system-generated",
            overall=confidence_overall,
        ),
    )


class TestRoadmapProtocol:
    def test_default_policy_satisfies_protocol(self, sample_rules: dict) -> None:
        policy = DefaultRoadmapPolicy(rules=sample_rules)
        assert isinstance(policy, RoadmapPolicy)


class TestPhaseAssignment:
    def test_critical_gets_immediate(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.CRITICAL)
        policy = DefaultRoadmapPolicy(rules=sample_rules)
        assignments = policy.assign_phases(findings=[cf])
        assert len(assignments) == 1
        assert assignments[0].phase == "IMMEDIATE"

    def test_high_gets_short_term(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.HIGH)
        policy = DefaultRoadmapPolicy(rules=sample_rules)
        assignments = policy.assign_phases(findings=[cf])
        assert assignments[0].phase == "SHORT_TERM"

    def test_medium_gets_medium_term(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.MEDIUM)
        policy = DefaultRoadmapPolicy(rules=sample_rules)
        assignments = policy.assign_phases(findings=[cf])
        assert assignments[0].phase == "MEDIUM_TERM"

    def test_low_gets_long_term(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.LOW)
        policy = DefaultRoadmapPolicy(rules=sample_rules)
        assignments = policy.assign_phases(findings=[cf])
        assert assignments[0].phase == "LONG_TERM"

    def test_info_gets_long_term(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.INFO)
        policy = DefaultRoadmapPolicy(rules=sample_rules)
        assignments = policy.assign_phases(findings=[cf])
        assert assignments[0].phase == "LONG_TERM"

    def test_timeline_populated(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.CRITICAL)
        policy = DefaultRoadmapPolicy(rules=sample_rules)
        assignments = policy.assign_phases(findings=[cf])
        assert assignments[0].timeline == "0-30 days"


class TestPriorityScoring:
    def test_critical_higher_priority_than_low(self, sample_rules: dict) -> None:
        cf_critical = _make_consolidated(severity=Severity.CRITICAL, instance_id="uuid-001")
        cf_low = _make_consolidated(
            severity=Severity.LOW,
            instance_id="uuid-002",
            finding_key="cis:m365:9.9.9",
        )
        policy = DefaultRoadmapPolicy(rules=sample_rules)
        assignments = policy.assign_phases(findings=[cf_critical, cf_low])
        critical_assign = next(a for a in assignments if a.finding_instance_id == "uuid-001")
        low_assign = next(a for a in assignments if a.finding_instance_id == "uuid-002")
        assert critical_assign.priority_score > low_assign.priority_score

    def test_priority_score_bounded(self, sample_rules: dict) -> None:
        cf = _make_consolidated(severity=Severity.CRITICAL, confidence_overall=1.0)
        policy = DefaultRoadmapPolicy(rules=sample_rules)
        assignments = policy.assign_phases(findings=[cf])
        assert 0.0 <= assignments[0].priority_score <= 100.0

    def test_higher_category_weight_increases_priority(self, sample_rules: dict) -> None:
        cf_identity = _make_consolidated(
            severity=Severity.MEDIUM,
            category=Category.IDENTITY_ACCESS,
            instance_id="uuid-001",
            finding_key="cis:m365:1.1.1",
        )
        cf_cost = _make_consolidated(
            severity=Severity.MEDIUM,
            category=Category.COST_OPTIMIZATION,
            instance_id="uuid-002",
            finding_key="cis:m365:9.9.9",
        )
        policy = DefaultRoadmapPolicy(rules=sample_rules)
        assignments = policy.assign_phases(findings=[cf_identity, cf_cost])
        identity_assign = next(a for a in assignments if a.finding_instance_id == "uuid-001")
        cost_assign = next(a for a in assignments if a.finding_instance_id == "uuid-002")
        assert identity_assign.priority_score > cost_assign.priority_score


class TestPhaseAssignmentFallback:
    def test_unmapped_severity_defaults_to_medium_term_and_logs_warning(
        self,
        sample_rules: dict,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """G11: A severity value absent from severity_to_phase falls back to MEDIUM_TERM
        and emits a WARNING that names the severity value. (finding_key is at DEBUG level
        after S2 fix and must NOT appear in the WARNING message.)"""
        rules_no_info_phase = {
            **sample_rules,
            "severity_to_phase": {
                # Intentionally omit "INFO" so it hits the fallback
                "CRITICAL": "IMMEDIATE",
                "HIGH": "SHORT_TERM",
                "MEDIUM": "MEDIUM_TERM",
                "LOW": "LONG_TERM",
            },
        }
        cf = _make_consolidated(severity=Severity.INFO, finding_key="cis:m365:9.9.9")
        policy = DefaultRoadmapPolicy(rules=rules_no_info_phase)

        with caplog.at_level(logging.WARNING, logger="gxassessms.policy.roadmap"):
            assignments = policy.assign_phases(findings=[cf])

        assert assignments[0].phase == "MEDIUM_TERM"
        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("INFO" in msg for msg in warning_messages), (
            "Warning must include the severity value"
        )


class TestEmptyInput:
    def test_empty_findings_returns_empty(self, sample_rules: dict) -> None:
        policy = DefaultRoadmapPolicy(rules=sample_rules)
        assignments = policy.assign_phases(findings=[])
        assert assignments == []

    def test_assignments_returned_in_priority_order(self, sample_rules: dict) -> None:
        low_finding = _make_consolidated(severity=Severity.LOW)
        critical_finding = _make_consolidated(severity=Severity.CRITICAL)
        policy = DefaultRoadmapPolicy(rules=sample_rules)
        assignments = policy.assign_phases(findings=[low_finding, critical_finding])
        assert len(assignments) == 2
        assert assignments[0].priority_score >= assignments[1].priority_score
