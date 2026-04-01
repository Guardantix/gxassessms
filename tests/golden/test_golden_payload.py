"""Golden file regression test for ReportPayload assembly.

Generates a payload from known fixture data and compares against a
committed JSON file. Catches unintentional changes to payload structure
or field serialization.

To update the golden file after an intentional change:
    UPDATE_GOLDEN=1 python3 -m pytest tests/golden/test_golden_payload.py -v
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from gxassessms.reporting.payload import assemble_payload

GOLDEN_DIR = Path(__file__).parent
GOLDEN_FILE = GOLDEN_DIR / "sample_engagement_payload.json"


def _make_golden_findings() -> list[dict[str, Any]]:
    return [
        {
            "finding_instance_id": "fi-golden-001",
            "finding_key": "fk-mfa-gaps",
            "title": "MFA Not Enforced for All Users",
            "severity": "HIGH",
            "status": "FAIL",
            "category": "IDENTITY_ACCESS",
            "description": (
                "Multi-factor authentication is not enforced for all users in the tenant."
            ),
            "sources": json.dumps([{"tool": "ScubaGear", "check_id": "MS.AAD.3.1v1"}]),
            "confidence": json.dumps({"overall": 0.9, "label": "HIGH"}),
            "benchmark_refs": json.dumps(["CIS-M365-5.1.2.3"]),
            "root_cause": "Conditional Access policies do not cover all user groups.",
            "remediation": "Configure Conditional Access policy to require MFA for all users.",
            "narrative": "This finding represents a critical identity protection gap.",
        },
        {
            "finding_instance_id": "fi-golden-002",
            "finding_key": "fk-audit-logging",
            "title": "Audit Logging Disabled",
            "severity": "MEDIUM",
            "status": "FAIL",
            "category": "LOGGING_MONITORING",
            "description": "Unified audit logging is not enabled in the tenant.",
            "sources": json.dumps([{"tool": "ScubaGear", "check_id": "MS.EXO.1.1v1"}]),
            "confidence": json.dumps({"overall": 0.85, "label": "HIGH"}),
            "benchmark_refs": json.dumps([]),
            "root_cause": None,
            "remediation": "Enable unified audit logging in the Security & Compliance Center.",
            "narrative": None,
        },
    ]


def _make_golden_coverage() -> list[dict[str, Any]]:
    return [
        {
            "control_id": "MS.AAD.3.1v1",
            "tool_source": "ScubaGear",
            "status": "ASSESSED",
            "reason": None,
        },
        {
            "control_id": "MS.EXO.1.1v1",
            "tool_source": "ScubaGear",
            "status": "ASSESSED",
            "reason": None,
        },
    ]


def _build_golden_payload() -> dict[str, Any]:
    finding_repo = MagicMock()
    finding_repo.get_consolidated.return_value = _make_golden_findings()

    coverage_repo = MagicMock()
    coverage_repo.get_for_engagement.return_value = _make_golden_coverage()

    payload = assemble_payload(
        engagement_id="eng-golden-001",
        tenant_name="Golden Test Client",
        assessment_date="2026-03-25T10:00:00Z",
        tool_sources=["ScubaGear"],
        finding_repo=finding_repo,
        coverage_repo=coverage_repo,
        narratives={
            "executive_summary": (
                "The assessed tenant shows significant gaps in identity "
                "protection and audit logging."
            ),
        },
    )

    return json.loads(payload.model_dump_json())


class TestGoldenPayload:
    def test_payload_matches_golden_file(self) -> None:
        actual = _build_golden_payload()

        if os.environ.get("UPDATE_GOLDEN") == "1":
            GOLDEN_FILE.write_text(
                json.dumps(actual, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            pytest.skip("Golden file updated -- re-run without UPDATE_GOLDEN")

        expected = json.loads(GOLDEN_FILE.read_text(encoding="utf-8"))

        actual_sorted = json.dumps(actual, indent=2, sort_keys=True)
        expected_sorted = json.dumps(expected, indent=2, sort_keys=True)

        assert actual_sorted == expected_sorted, (
            "Payload does not match golden file. "
            "If this change is intentional, run: "
            "UPDATE_GOLDEN=1 python3 -m pytest tests/golden/test_golden_payload.py -v"
        )

    def test_golden_file_is_valid_json(self) -> None:
        content = GOLDEN_FILE.read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert isinstance(parsed, dict)

    def test_golden_file_has_required_fields(self) -> None:
        content = json.loads(GOLDEN_FILE.read_text(encoding="utf-8"))
        required_fields = {
            "schema_version",
            "engagement_id",
            "tenant_name",
            "assessment_date",
            "tool_sources",
            "findings",
            "coverage",
            "narratives",
            "metadata",
        }
        assert required_fields.issubset(set(content.keys())), (
            f"Missing fields: {required_fields - set(content.keys())}"
        )

    def test_golden_file_schema_version(self) -> None:
        content = json.loads(GOLDEN_FILE.read_text(encoding="utf-8"))
        assert content["schema_version"] == "1.0.0"
