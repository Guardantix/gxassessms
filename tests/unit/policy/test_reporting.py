"""Tests for ReportingPolicy -- suppression, filtering, audience thresholds."""

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
from gxassessms.policy.reporting import (
    DefaultReportingPolicy,
    ReportingPolicy,
)


@pytest.fixture
def sample_rules() -> dict:
    return {
        "audiences": {
            "executive": {
                "minimum_severity": "HIGH",
                "minimum_confidence": 0.5,
                "max_findings": 20,
                "sections": ["executive_summary", "key_findings", "roadmap"],
            },
            "technical": {
                "minimum_severity": "INFO",
                "minimum_confidence": 0.0,
                "max_findings": None,
                "sections": [
                    "executive_summary",
                    "detailed_findings",
                    "methodology",
                ],
            },
        },
        "suppression_rules": [
            {
                "field": "status",
                "value": "PASS",
                "reason": "Passing checks not reported",
            },
            {
                "field": "status",
                "value": "N/A",
                "reason": "Not-applicable excluded",
            },
        ],
        "redaction": {
            "executive_redacted_patterns": [
                "tenant_id",
                "client_secret",
            ],
        },
        "display": {
            "default_sort": "severity",
            "sort_descending": True,
            "group_by": "category",
        },
    }


def _make_finding(
    *,
    severity: Severity = Severity.CRITICAL,
    status: FindingStatus = FindingStatus.FAIL,
    confidence_overall: float = 0.88,
    category: Category = Category.IDENTITY_ACCESS,
    instance_id: str = "uuid-001",
    finding_key: str = "cis:m365:1.1.1",
    description: str = "Test finding description",
) -> ConsolidatedFinding:
    return ConsolidatedFinding(
        finding_instance_id=instance_id,
        finding_key=finding_key,
        title="Test finding",
        severity=severity,
        status=status,
        category=category,
        description=description,
        sources=[
            SourceEvidence(
                tool=ToolSource.SCUBAGEAR,
                check_id="MS.AAD.3.1v1",
                raw_data={},
            )
        ],
        confidence=ConfidenceScore(
            evidence_strength=0.8,
            corroborating_tools=2,
            data_freshness=1.0,
            provenance="system-generated",
            overall=confidence_overall,
        ),
    )


class TestReportingProtocol:
    def test_default_policy_satisfies_protocol(self, sample_rules: dict) -> None:
        policy = DefaultReportingPolicy(rules=sample_rules)
        assert isinstance(policy, ReportingPolicy)


class TestSuppression:
    def test_passing_findings_suppressed(self, sample_rules: dict) -> None:
        cf = _make_finding(status=FindingStatus.PASS)
        policy = DefaultReportingPolicy(rules=sample_rules)
        filtered = policy.apply_suppression(findings=[cf])
        assert len(filtered) == 0

    def test_na_findings_suppressed(self, sample_rules: dict) -> None:
        cf = _make_finding(status=FindingStatus.NOT_APPLICABLE)
        policy = DefaultReportingPolicy(rules=sample_rules)
        filtered = policy.apply_suppression(findings=[cf])
        assert len(filtered) == 0

    def test_failing_findings_not_suppressed(self, sample_rules: dict) -> None:
        cf = _make_finding(status=FindingStatus.FAIL)
        policy = DefaultReportingPolicy(rules=sample_rules)
        filtered = policy.apply_suppression(findings=[cf])
        assert len(filtered) == 1

    def test_warning_findings_not_suppressed(self, sample_rules: dict) -> None:
        cf = _make_finding(status=FindingStatus.WARNING)
        policy = DefaultReportingPolicy(rules=sample_rules)
        filtered = policy.apply_suppression(findings=[cf])
        assert len(filtered) == 1

    def test_category_suppression_by_enum_name(self, sample_rules: dict) -> None:
        rules = {
            **sample_rules,
            "suppression_rules": [{"field": "category", "value": "COMPLIANCE"}],
        }
        cf = _make_finding(category=Category.COMPLIANCE)
        policy = DefaultReportingPolicy(rules=rules)
        filtered = policy.apply_suppression(findings=[cf])
        assert len(filtered) == 0

    def test_category_suppression_by_display_value(self, sample_rules: dict) -> None:
        rules = {
            **sample_rules,
            "suppression_rules": [{"field": "category", "value": Category.COMPLIANCE.value}],
        }
        cf = _make_finding(category=Category.COMPLIANCE)
        policy = DefaultReportingPolicy(rules=rules)
        filtered = policy.apply_suppression(findings=[cf])
        assert len(filtered) == 0


class TestAudienceFiltering:
    def test_executive_filters_below_high(self, sample_rules: dict) -> None:
        findings = [
            _make_finding(
                severity=Severity.CRITICAL,
                instance_id="uuid-001",
                finding_key="cis:m365:1.1.1",
            ),
            _make_finding(
                severity=Severity.HIGH,
                instance_id="uuid-002",
                finding_key="cis:m365:1.1.2",
            ),
            _make_finding(
                severity=Severity.MEDIUM,
                instance_id="uuid-003",
                finding_key="cis:m365:2.1.1",
            ),
            _make_finding(
                severity=Severity.LOW,
                instance_id="uuid-004",
                finding_key="cis:m365:3.1.1",
            ),
        ]
        policy = DefaultReportingPolicy(rules=sample_rules)
        filtered = policy.filter_for_audience(findings=findings, audience="executive")
        assert len(filtered) == 2
        severities = {f.severity for f in filtered}
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.MEDIUM not in severities

    def test_technical_shows_all_severities(self, sample_rules: dict) -> None:
        findings = [
            _make_finding(
                severity=Severity.CRITICAL,
                instance_id="uuid-001",
                finding_key="cis:m365:1.1.1",
            ),
            _make_finding(
                severity=Severity.INFO,
                instance_id="uuid-002",
                finding_key="cis:m365:9.9.9",
            ),
        ]
        policy = DefaultReportingPolicy(rules=sample_rules)
        filtered = policy.filter_for_audience(findings=findings, audience="technical")
        assert len(filtered) == 2

    def test_executive_filters_low_confidence(self, sample_rules: dict) -> None:
        cf = _make_finding(
            severity=Severity.CRITICAL,
            confidence_overall=0.3,
        )
        policy = DefaultReportingPolicy(rules=sample_rules)
        filtered = policy.filter_for_audience(findings=[cf], audience="executive")
        assert len(filtered) == 0

    def test_executive_max_findings_limit(self, sample_rules: dict) -> None:
        # Create 25 findings (over the executive limit of 20)
        findings = [
            _make_finding(
                severity=Severity.CRITICAL,
                instance_id=f"uuid-{i:03d}",
                finding_key=f"cis:m365:{i}.1.1",
            )
            for i in range(25)
        ]
        policy = DefaultReportingPolicy(rules=sample_rules)
        filtered = policy.filter_for_audience(findings=findings, audience="executive")
        assert len(filtered) == 20

    def test_unknown_audience_returns_all(self, sample_rules: dict) -> None:
        cf = _make_finding()
        policy = DefaultReportingPolicy(rules=sample_rules)
        filtered = policy.filter_for_audience(findings=[cf], audience="unknown_audience")
        assert len(filtered) == 1

    def test_unknown_audience_logs_warning(
        self,
        sample_rules: dict,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """G10: Unknown audience name triggers a WARNING log that includes the audience
        string -- added as a new log call in this diff."""
        policy = DefaultReportingPolicy(rules=sample_rules)
        cf = _make_finding()

        with caplog.at_level(logging.WARNING, logger="gxassessms.policy.reporting"):
            result = policy.filter_for_audience(findings=[cf], audience="mystery_audience")

        assert len(result) == 1  # returns all unfiltered
        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("mystery_audience" in msg for msg in warning_messages), (
            "Warning must name the unrecognized audience for operator diagnosis"
        )

    def test_filter_for_audience_sorted_by_severity_desc(self, sample_rules: dict) -> None:
        findings = [
            _make_finding(
                severity=Severity.LOW,
                confidence_overall=0.9,
                instance_id="uuid-001",
                finding_key="cis:m365:3.1.1",
            ),
            _make_finding(
                severity=Severity.CRITICAL,
                confidence_overall=0.9,
                instance_id="uuid-002",
                finding_key="cis:m365:1.1.1",
            ),
            _make_finding(
                severity=Severity.MEDIUM,
                confidence_overall=0.9,
                instance_id="uuid-003",
                finding_key="cis:m365:2.1.1",
            ),
        ]
        policy = DefaultReportingPolicy(rules=sample_rules)
        result = policy.filter_for_audience(findings, "technical")
        assert result[0].severity == Severity.CRITICAL
        assert result[-1].severity == Severity.LOW


class TestAudienceSections:
    def test_get_sections_for_executive(self, sample_rules: dict) -> None:
        policy = DefaultReportingPolicy(rules=sample_rules)
        sections = policy.get_sections(audience="executive")
        assert "executive_summary" in sections
        assert "key_findings" in sections
        assert "detailed_findings" not in sections

    def test_get_sections_for_technical(self, sample_rules: dict) -> None:
        policy = DefaultReportingPolicy(rules=sample_rules)
        sections = policy.get_sections(audience="technical")
        assert "detailed_findings" in sections
        assert "methodology" in sections

    def test_get_sections_unknown_audience(self, sample_rules: dict) -> None:
        policy = DefaultReportingPolicy(rules=sample_rules)
        sections = policy.get_sections(audience="nonexistent")
        assert sections == []


class TestDisplayConfig:
    def test_get_display_config(self, sample_rules: dict) -> None:
        policy = DefaultReportingPolicy(rules=sample_rules)
        config = policy.get_display_config()
        assert config["default_sort"] == "severity"
        assert config["sort_descending"] is True
        assert config["group_by"] == "category"


class TestEmptyInput:
    def test_empty_findings_suppression(self, sample_rules: dict) -> None:
        policy = DefaultReportingPolicy(rules=sample_rules)
        assert policy.apply_suppression(findings=[]) == []

    def test_empty_findings_audience_filter(self, sample_rules: dict) -> None:
        policy = DefaultReportingPolicy(rules=sample_rules)
        assert policy.filter_for_audience(findings=[], audience="executive") == []
