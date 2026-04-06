"""Tests for Monkey365 OCSF parser -- transforms Detection Findings into ToolObservations."""

import json
from pathlib import Path
from typing import Any

import pytest

from gxassessms.adapters.monkey365.parser import (
    extract_id_suffix,
    parse_monkey365_findings,
)
from gxassessms.core.domain.models import ToolObservation


@pytest.fixture(scope="module")
def fixture_data() -> list[dict[str, Any]]:
    """Load the Monkey365 OCSF fixture data."""
    fixture_path = (
        Path(__file__).parent.parent.parent.parent
        / "src"
        / "gxassessms"
        / "adapters"
        / "monkey365"
        / "fixtures"
        / "monkey365_sample.json"
    )
    with open(fixture_path) as f:
        return json.load(f)


class TestExtractIdSuffix:
    """Test idSuffix extraction from findingInfo.id."""

    def test_standard_format(self) -> None:
        fid = (
            "Monkey365-aad-lack-cloud-only-accounts"
            "-00000000000000000000000000000000-abcdef1234567890abcd"
        )
        assert extract_id_suffix(fid) == "aad_lack_cloud_only_accounts"

    def test_longer_suffix(self) -> None:
        fid = (
            "Monkey365-eid-privileged-users-reduced-application-footprint-license"
            "-00000000000000000000000000000000-176639065c10451a8982"
        )
        assert (
            extract_id_suffix(fid) == "eid_privileged_users_reduced_application_footprint_license"
        )

    def test_exchange_suffix(self) -> None:
        fid = (
            "Monkey365-m365-exo-transport-rules-forwarding-external"
            "-00000000000000000000000000000000-d4e5f6a7b8c9d0e1f2a3"
        )
        assert extract_id_suffix(fid) == "m365_exo_transport_rules_forwarding_external"

    def test_returns_none_for_malformed(self) -> None:
        assert extract_id_suffix("not-a-valid-id") is None
        assert extract_id_suffix("") is None


class TestParseMonkey365Findings:
    """Test full parsing pipeline."""

    def test_returns_list_of_tool_observations(self, fixture_data: list[dict[str, Any]]) -> None:
        observations = parse_monkey365_findings(fixture_data)
        assert isinstance(observations, list)
        assert all(isinstance(o, ToolObservation) for o in observations)

    def test_observation_count_matches_input(self, fixture_data: list[dict[str, Any]]) -> None:
        observations = parse_monkey365_findings(fixture_data)
        assert len(observations) == len(fixture_data)

    def test_native_check_id_is_idsuffix(self, fixture_data: list[dict[str, Any]]) -> None:
        observations = parse_monkey365_findings(fixture_data)
        first = observations[0]
        assert first.native_check_id == "aad_lack_cloud_only_accounts"

    def test_native_severity_is_raw_string(self, fixture_data: list[dict[str, Any]]) -> None:
        """Parser stores raw OCSF severity strings; normalization maps later."""
        observations = parse_monkey365_findings(fixture_data)
        assert observations[0].native_severity == "Unknown"
        assert observations[3].native_severity == "High"
        assert observations[4].native_severity == "Critical"

    def test_native_status_is_raw_string(self, fixture_data: list[dict[str, Any]]) -> None:
        """Parser stores raw OCSF statusCode; normalization maps later."""
        observations = parse_monkey365_findings(fixture_data)
        assert observations[0].native_status == "pass"
        assert observations[1].native_status == "manual"
        assert observations[3].native_status == "fail"

    def test_title_from_finding_info(self, fixture_data: list[dict[str, Any]]) -> None:
        observations = parse_monkey365_findings(fixture_data)
        expected = "Ensure Administrative accounts are separate and cloud-only"
        assert observations[0].title == expected

    def test_description_from_finding_info(self, fixture_data: list[dict[str, Any]]) -> None:
        observations = parse_monkey365_findings(fixture_data)
        assert "Administrative accounts" in observations[0].description

    def test_observation_id_format(self, fixture_data: list[dict[str, Any]]) -> None:
        """observation_id follows monkey365:{native_check_id} format."""
        observations = parse_monkey365_findings(fixture_data)
        assert observations[0].observation_id == "monkey365:aad_lack_cloud_only_accounts"

    def test_tool_is_monkey365(self, fixture_data: list[dict[str, Any]]) -> None:
        """Every observation has tool=ToolSource.MONKEY365."""
        from gxassessms.core.domain.enums import ToolSource

        observations = parse_monkey365_findings(fixture_data)
        for obs in observations:
            assert obs.tool == ToolSource.MONKEY365

    def test_empty_input(self) -> None:
        assert parse_monkey365_findings([]) == []
