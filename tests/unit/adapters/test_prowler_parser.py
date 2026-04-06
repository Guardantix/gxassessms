"""Tests for Prowler OCSF parser -- transforms Detection Findings into ToolObservations."""

from __future__ import annotations

from typing import Any

import pytest

from gxassessms.adapters.prowler.parser import parse_prowler_findings
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import ToolObservation


@pytest.fixture
def fixture_data(prowler_fixture_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Alias for shared prowler_fixture_data fixture."""
    return prowler_fixture_data


class TestParseProwlerFindings:
    """Test full parsing pipeline."""

    def test_returns_list_of_tool_observations(self, fixture_data: list[dict]) -> None:
        observations = parse_prowler_findings(fixture_data)
        assert isinstance(observations, list)
        assert all(isinstance(o, ToolObservation) for o in observations)

    def test_observation_count_matches_input(self, fixture_data: list[dict]) -> None:
        observations = parse_prowler_findings(fixture_data)
        assert len(observations) == len(fixture_data)

    def test_native_check_id_from_metadata_event_code(self, fixture_data: list[dict]) -> None:
        """Check ID comes from metadata.event_code, NOT finding_info.uid."""
        observations = parse_prowler_findings(fixture_data)
        first = observations[0]
        assert first.native_check_id == "defender_ensure_defender_for_app_services_is_on"

    def test_native_check_id_not_finding_uid(self, fixture_data: list[dict]) -> None:
        """Verify the parser does NOT use finding_info.uid as check ID."""
        observations = parse_prowler_findings(fixture_data)
        first = observations[0]
        # finding_info.uid contains per-finding unique ID with subscription/resource info
        assert "prowler-azure-" not in first.native_check_id

    def test_severity_preserved_as_string(self, fixture_data: list[dict]) -> None:
        """native_severity is the OCSF severity string (title case)."""
        observations = parse_prowler_findings(fixture_data)
        # First finding: severity "Medium"
        assert observations[0].native_severity == "Medium"
        # Third finding: severity "High"
        assert observations[2].native_severity == "High"
        # Fifth finding: severity "Low"
        assert observations[4].native_severity == "Low"

    def test_status_from_status_code_not_status(self, fixture_data: list[dict]) -> None:
        """native_status comes from status_code (UPPERCASE), not status ("New")."""
        observations = parse_prowler_findings(fixture_data)
        # First finding: status_code "FAIL"
        assert observations[0].native_status == "FAIL"
        # Second finding: status_code "PASS"
        assert observations[1].native_status == "PASS"
        # Fifth finding: status_code "MANUAL"
        assert observations[4].native_status == "MANUAL"

    def test_title_from_finding_info(self, fixture_data: list[dict]) -> None:
        observations = parse_prowler_findings(fixture_data)
        assert (
            observations[0].title
            == "Ensure That Microsoft Defender for App Services Is Set To 'On'"
        )

    def test_description_from_finding_info_desc(self, fixture_data: list[dict]) -> None:
        """Description comes from finding_info.desc (not 'description')."""
        observations = parse_prowler_findings(fixture_data)
        assert "threat detection" in observations[0].description

    def test_benchmark_refs_from_compliance(self, fixture_data: list[dict]) -> None:
        """benchmark_refs populated from unmapped.compliance."""
        observations = parse_prowler_findings(fixture_data)
        first = observations[0]
        # First finding has CIS-2.1: ["5.3.1"] and CIS-3.0: ["6.3.1"]
        assert "CIS-2.1:5.3.1" in first.benchmark_refs
        assert "CIS-3.0:6.3.1" in first.benchmark_refs

    def test_observation_id_format(self, fixture_data: list[dict]) -> None:
        """observation_id follows prowler:{native_check_id}:{uid_hash} format."""
        observations = parse_prowler_findings(fixture_data)
        first = observations[0]
        assert first.observation_id.startswith("prowler:")
        assert "defender_ensure_defender_for_app_services_is_on" in first.observation_id

    def test_tool_is_prowler(self, fixture_data: list[dict]) -> None:
        observations = parse_prowler_findings(fixture_data)
        for obs in observations:
            assert obs.tool == ToolSource.PROWLER

    def test_raw_data_preserved(self, fixture_data: list[dict]) -> None:
        """raw_data contains the original OCSF finding dict."""
        observations = parse_prowler_findings(fixture_data)
        first = observations[0]
        assert (
            first.raw_data.get("metadata", {}).get("event_code")
            == "defender_ensure_defender_for_app_services_is_on"
        )

    def test_empty_input(self) -> None:
        assert parse_prowler_findings([]) == []

    def test_multiple_findings_same_check_different_resources(self) -> None:
        """Prowler produces one finding per resource. Multiple findings with the
        same check ID but different resources should produce separate observations."""
        findings = [
            {
                "finding_info": {
                    "desc": "Check desc",
                    "title": "Check title",
                    "uid": (
                        "prowler-azure-storage_secure_transfer_required_is_enabled"
                        "-sub1-eastus-storage1"
                    ),
                    "name": "storage1",
                    "types": [],
                },
                "metadata": {"event_code": "storage_secure_transfer_required_is_enabled"},
                "severity": "High",
                "status_code": "PASS",
                "status": "New",
                "resources": [{"group": {"name": "storage"}, "uid": "uid1"}],
                "remediation": {"desc": "", "references": []},
                "unmapped": {"compliance": {}, "provider": "azure"},
                "cloud": {"provider": "azure"},
            },
            {
                "finding_info": {
                    "desc": "Check desc",
                    "title": "Check title",
                    "uid": (
                        "prowler-azure-storage_secure_transfer_required_is_enabled"
                        "-sub1-eastus-storage2"
                    ),
                    "name": "storage2",
                    "types": [],
                },
                "metadata": {"event_code": "storage_secure_transfer_required_is_enabled"},
                "severity": "High",
                "status_code": "FAIL",
                "status": "New",
                "resources": [{"group": {"name": "storage"}, "uid": "uid2"}],
                "remediation": {"desc": "", "references": []},
                "unmapped": {"compliance": {}, "provider": "azure"},
                "cloud": {"provider": "azure"},
            },
        ]
        observations = parse_prowler_findings(findings)
        assert len(observations) == 2
        assert observations[0].native_check_id == observations[1].native_check_id
        assert observations[0].observation_id != observations[1].observation_id
