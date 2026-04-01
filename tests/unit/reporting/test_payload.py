"""Tests for payload assembly -- builds ReportPayload from engagement data."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

from gxassessms.core.domain.models import ReportPayload
from gxassessms.reporting.payload import assemble_payload


def _make_consolidated_findings() -> list[dict[str, Any]]:
    """Create sample consolidated findings as returned by FindingRepo.get_consolidated()."""
    return [
        {
            "finding_instance_id": "fi-001",
            "finding_key": "fk-mfa-gaps",
            "title": "MFA Not Enforced for All Users",
            "severity": "HIGH",
            "status": "FAIL",
            "category": "IDENTITY_ACCESS",
            "description": "Multi-factor authentication is not enforced for all users.",
            "sources": json.dumps(
                [
                    {"tool": "ScubaGear", "check_id": "MS.AAD.3.1v1"},
                ]
            ),
            "confidence": json.dumps({"overall": 0.9, "label": "HIGH"}),
            "benchmark_refs": json.dumps(["CIS-M365-5.1.2.3"]),
            "root_cause": "Conditional Access policies incomplete",
            "remediation": "Configure CA policy to require MFA for all users",
            "narrative": "This finding indicates a significant gap in identity protection.",
        },
        {
            "finding_instance_id": "fi-002",
            "finding_key": "fk-audit-logging",
            "title": "Audit Logging Disabled",
            "severity": "MEDIUM",
            "status": "FAIL",
            "category": "LOGGING_MONITORING",
            "description": "Unified audit logging is not enabled in the tenant.",
            "sources": json.dumps(
                [
                    {"tool": "ScubaGear", "check_id": "MS.EXO.1.1v1"},
                ]
            ),
            "confidence": json.dumps({"overall": 0.85, "label": "HIGH"}),
            "benchmark_refs": json.dumps([]),
            "root_cause": None,
            "remediation": "Enable unified audit logging",
            "narrative": None,
        },
    ]


def _make_coverage_records() -> list[dict[str, Any]]:
    """Create sample coverage records as returned by CoverageRepo.get_for_engagement()."""
    return [
        {
            "control_id": "MS.AAD.3.1v1",
            "tool_source": "ScubaGear",
            "status": "assessed",
            "reason": None,
        },
        {
            "control_id": "MS.EXO.1.1v1",
            "tool_source": "ScubaGear",
            "status": "assessed",
            "reason": None,
        },
        {
            "control_id": "MS.SPO.1.1v1",
            "tool_source": "ScubaGear",
            "status": "not_assessed",
            "reason": "Module skipped",
        },
    ]


def _make_mock_repos(
    findings: list[dict[str, Any]],
    coverage: list[dict[str, Any]],
) -> tuple[MagicMock, MagicMock]:
    """Create mock repositories returning the given data."""
    finding_repo = MagicMock()
    finding_repo.get_consolidated.return_value = findings

    coverage_repo = MagicMock()
    coverage_repo.get_for_engagement.return_value = coverage

    return finding_repo, coverage_repo


class TestAssemblePayload:
    def test_returns_report_payload(self) -> None:
        find_repo, cov_repo = _make_mock_repos(
            _make_consolidated_findings(), _make_coverage_records()
        )
        result = assemble_payload(
            engagement_id="eng-001",
            tenant_name="Acme Healthcare",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=["ScubaGear"],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
        )
        assert isinstance(result, ReportPayload)

    def test_schema_version_is_set(self) -> None:
        find_repo, cov_repo = _make_mock_repos(
            _make_consolidated_findings(), _make_coverage_records()
        )
        result = assemble_payload(
            engagement_id="eng-001",
            tenant_name="Acme Healthcare",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=["ScubaGear"],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
        )
        assert result.schema_version == "1.0.0"

    def test_engagement_fields(self) -> None:
        find_repo, cov_repo = _make_mock_repos(
            _make_consolidated_findings(), _make_coverage_records()
        )
        result = assemble_payload(
            engagement_id="eng-001",
            tenant_name="Acme Healthcare",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=["ScubaGear"],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
        )
        assert result.engagement_id == "eng-001"
        assert result.tenant_name == "Acme Healthcare"
        assert result.assessment_date == "2026-03-25T10:00:00Z"

    def test_findings_populated(self) -> None:
        findings = _make_consolidated_findings()
        find_repo, cov_repo = _make_mock_repos(findings, _make_coverage_records())
        result = assemble_payload(
            engagement_id="eng-001",
            tenant_name="Acme Healthcare",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=["ScubaGear"],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
        )
        assert len(result.findings) == 2
        assert result.findings[0]["title"] == "MFA Not Enforced for All Users"

    def test_coverage_populated(self) -> None:
        find_repo, cov_repo = _make_mock_repos(
            _make_consolidated_findings(), _make_coverage_records()
        )
        result = assemble_payload(
            engagement_id="eng-001",
            tenant_name="Acme Healthcare",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=["ScubaGear"],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
        )
        assert len(result.coverage) == 3
        assert result.coverage[0]["control_id"] == "MS.AAD.3.1v1"

    def test_tool_sources_passed_through(self) -> None:
        find_repo, cov_repo = _make_mock_repos(
            _make_consolidated_findings(), _make_coverage_records()
        )
        result = assemble_payload(
            engagement_id="eng-001",
            tenant_name="Test",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=["ScubaGear", "Maester"],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
        )
        assert result.tool_sources == ["ScubaGear", "Maester"]

    def test_narratives_populated(self) -> None:
        find_repo, cov_repo = _make_mock_repos(
            _make_consolidated_findings(), _make_coverage_records()
        )
        result = assemble_payload(
            engagement_id="eng-001",
            tenant_name="Test",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=["ScubaGear"],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
            narratives={
                "executive_summary": "The tenant has significant gaps.",
                "roadmap": "Phase 1 addresses critical items.",
            },
        )
        assert result.narratives["executive_summary"] == "The tenant has significant gaps."
        assert result.narratives["roadmap"] == "Phase 1 addresses critical items."

    def test_narratives_default_to_none_placeholders(self) -> None:
        find_repo, cov_repo = _make_mock_repos([], [])
        result = assemble_payload(
            engagement_id="eng-001",
            tenant_name="Test",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=[],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
        )
        assert result.narratives == {
            "executive_summary": None,
            "roadmap": None,
            "findings_narrative": None,
        }

    def test_metadata_includes_config_snapshot(self) -> None:
        find_repo, cov_repo = _make_mock_repos([], [])
        config_snapshot = {"client": {"name": "Acme"}, "tools": {}}
        result = assemble_payload(
            engagement_id="eng-001",
            tenant_name="Test",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=[],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
            config_snapshot=config_snapshot,
        )
        assert result.metadata["config_snapshot"] == config_snapshot

    def test_empty_engagement(self) -> None:
        find_repo, cov_repo = _make_mock_repos([], [])
        result = assemble_payload(
            engagement_id="eng-001",
            tenant_name="Test",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=[],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
        )
        assert result.findings == []
        assert result.coverage == []
        assert result.tool_sources == []

    def test_repos_called_with_engagement_id(self) -> None:
        find_repo, cov_repo = _make_mock_repos([], [])
        assemble_payload(
            engagement_id="eng-001",
            tenant_name="Test",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=[],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
        )
        find_repo.get_consolidated.assert_called_once_with("eng-001")
        cov_repo.get_for_engagement.assert_called_once_with("eng-001")

    def test_findings_json_fields_deserialized(self) -> None:
        """sources, confidence, benchmark_refs stored as JSON strings in DB
        should be deserialized in payload."""
        findings = _make_consolidated_findings()
        find_repo, cov_repo = _make_mock_repos(findings, _make_coverage_records())
        result = assemble_payload(
            engagement_id="eng-001",
            tenant_name="Test",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=["ScubaGear"],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
        )
        sources = result.findings[0]["sources"]
        assert isinstance(sources, list)
        assert sources[0]["tool"] == "ScubaGear"

    def test_malformed_json_field_preserved_as_string(self) -> None:
        """Malformed JSON in a string field should be left as-is, not crash."""
        findings = [
            {
                "finding_instance_id": "fi-bad",
                "finding_key": "fk-bad",
                "title": "Bad Finding",
                "severity": "LOW",
                "status": "FAIL",
                "category": "IDENTITY_ACCESS",
                "description": "Test",
                "sources": "{not valid json",
                "confidence": json.dumps({"overall": 0.5, "label": "LOW"}),
                "benchmark_refs": json.dumps([]),
                "root_cause": None,
                "remediation": None,
                "narrative": None,
            },
        ]
        find_repo, cov_repo = _make_mock_repos(findings, [])
        result = assemble_payload(
            engagement_id="eng-001",
            tenant_name="Test",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=[],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
        )
        assert result.findings[0]["sources"] == "{not valid json"

    def test_payload_serializable_to_json(self) -> None:
        """ReportPayload must be fully JSON-serializable for Node.js consumption."""
        find_repo, cov_repo = _make_mock_repos(
            _make_consolidated_findings(), _make_coverage_records()
        )
        result = assemble_payload(
            engagement_id="eng-001",
            tenant_name="Test",
            assessment_date="2026-03-25T10:00:00Z",
            tool_sources=["ScubaGear"],
            finding_repo=find_repo,
            coverage_repo=cov_repo,
            narratives={"executive_summary": "Summary text."},
        )
        json_str = result.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["engagement_id"] == "eng-001"
