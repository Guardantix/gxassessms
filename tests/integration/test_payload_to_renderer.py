"""Integration test: payload assembly -> Node.js renderer -> .docx output.

Exercises the full rendering pipeline:
1. Assemble a ReportPayload from mock engagement data
2. Write payload JSON and constants.json to temp directory
3. Invoke the basic renderer via Node.js
4. Verify the output .docx exists and is non-zero bytes

Requires Node.js and npm install in the basic renderer directory.
Skipped automatically if either is unavailable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from gxassessms.reporting.payload import assemble_payload
from gxassessms.reporting.renderer_registry import NodeRenderer, check_node_available

_NODE_AVAILABLE = check_node_available()
_BASIC_RENDERER_DIR = Path(__file__).resolve().parent.parent.parent / "report-renderers" / "basic"
_NODE_MODULES_INSTALLED = (_BASIC_RENDERER_DIR / "node_modules").exists()

pytestmark = pytest.mark.skipif(
    not _NODE_AVAILABLE or not _NODE_MODULES_INSTALLED,
    reason="Node.js or basic renderer npm deps not available",
)


def _make_findings() -> list[dict[str, Any]]:
    return [
        {
            "finding_instance_id": "fi-integ-001",
            "finding_key": "fk-mfa-gaps",
            "title": "MFA Not Enforced",
            "severity": "HIGH",
            "status": "FAIL",
            "category": "IDENTITY_ACCESS",
            "description": "MFA is not enforced for all users.",
            "sources": json.dumps([{"tool": "ScubaGear", "check_id": "MS.AAD.3.1v1"}]),
            "confidence": json.dumps({"overall": 0.9, "label": "HIGH"}),
            "benchmark_refs": json.dumps(["CIS-M365-5.1.2.3"]),
            "root_cause": "Incomplete CA policies",
            "remediation": "Enable MFA for all users",
            "narrative": None,
        },
    ]


def _make_coverage() -> list[dict[str, Any]]:
    return [
        {
            "control_id": "MS.AAD.3.1v1",
            "tool_source": "ScubaGear",
            "status": "ASSESSED",
            "reason": None,
        },
    ]


def _assemble_test_payload(
    findings: list[dict[str, Any]] | None = None,
    coverage: list[dict[str, Any]] | None = None,
    narratives: dict[str, str | None] | None = None,
) -> Any:
    finding_repo = MagicMock()
    finding_repo.get_consolidated.return_value = findings or _make_findings()
    coverage_repo = MagicMock()
    coverage_repo.get_for_engagement.return_value = coverage or _make_coverage()

    return assemble_payload(
        engagement_id="eng-integ-001",
        tenant_name="Integration Test Client",
        assessment_date="2026-03-25T10:00:00Z",
        tool_sources=["ScubaGear"],
        finding_repo=finding_repo,
        coverage_repo=coverage_repo,
        narratives=narratives,
    )


class TestPayloadToRenderer:
    def test_basic_docx_render_produces_file(self, tmp_path: Path) -> None:
        payload = _assemble_test_payload(
            narratives={"executive_summary": "Integration test summary."},
        )

        renderer = NodeRenderer(
            package_path=_BASIC_RENDERER_DIR,
            format="docx",
            supported_payload_versions=">=1.0.0,<2.0.0",
        )

        result = renderer.render(payload, tmp_path)
        expected = tmp_path / "eng-integ-001.docx"

        assert result == expected
        assert expected.exists(), "Output .docx file should exist"
        assert expected.stat().st_size > 0, "Output .docx should be non-zero bytes"

    def test_basic_docx_render_with_empty_findings(self, tmp_path: Path) -> None:
        payload = _assemble_test_payload(findings=[], coverage=[])

        renderer = NodeRenderer(
            package_path=_BASIC_RENDERER_DIR,
            format="docx",
            supported_payload_versions=">=1.0.0,<2.0.0",
        )

        result = renderer.render(payload, tmp_path)
        assert result.exists()
        assert result.stat().st_size > 0

    def test_basic_docx_render_with_multiple_categories(self, tmp_path: Path) -> None:
        findings = _make_findings()
        findings.append(
            {
                "finding_instance_id": "fi-integ-002",
                "finding_key": "fk-audit-log",
                "title": "Audit Logging Disabled",
                "severity": "MEDIUM",
                "status": "FAIL",
                "category": "LOGGING_MONITORING",
                "description": "Audit logging is not enabled.",
                "sources": json.dumps([{"tool": "ScubaGear", "check_id": "MS.EXO.1.1v1"}]),
                "confidence": json.dumps({"overall": 0.85, "label": "HIGH"}),
                "benchmark_refs": json.dumps([]),
                "root_cause": None,
                "remediation": "Enable audit logging",
                "narrative": None,
            }
        )

        payload = _assemble_test_payload(
            findings=findings,
            narratives={"executive_summary": "Multi-category test."},
        )

        renderer = NodeRenderer(
            package_path=_BASIC_RENDERER_DIR,
            format="docx",
            supported_payload_versions=">=1.0.0,<2.0.0",
        )

        result = renderer.render(payload, tmp_path)
        assert result.exists()
        assert result.stat().st_size > 0
