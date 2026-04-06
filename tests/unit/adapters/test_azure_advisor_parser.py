"""Tests for Azure Advisor parser -- transforms API recommendations into ToolObservations."""

import json
from pathlib import Path

import pytest

from gxassessms.adapters.azure_advisor.parser import parse_advisor_recommendations
from gxassessms.core.domain.enums import FindingStatus, Severity, ToolSource
from gxassessms.core.domain.models import ToolObservation


@pytest.fixture
def fixture_data() -> dict:
    """Load the Azure Advisor fixture data."""
    fixture_path = (
        Path(__file__).parent.parent.parent.parent
        / "src"
        / "gxassessms"
        / "adapters"
        / "azure_advisor"
        / "fixtures"
        / "azure_advisor_sample.json"
    )
    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def recommendations(fixture_data: dict) -> list[dict]:
    """Extract the value array from fixture data."""
    return fixture_data["value"]


class TestParseAdvisorRecommendations:
    """Test full parsing pipeline."""

    def test_returns_list_of_tool_observations(
        self,
        recommendations: list[dict],
    ) -> None:
        observations = parse_advisor_recommendations(recommendations)
        assert isinstance(observations, list)
        assert all(isinstance(o, ToolObservation) for o in observations)

    def test_observation_count_matches_input(
        self,
        recommendations: list[dict],
    ) -> None:
        observations = parse_advisor_recommendations(recommendations)
        assert len(observations) == len(recommendations)

    def test_native_check_id_is_recommendation_type_id(
        self,
        recommendations: list[dict],
    ) -> None:
        observations = parse_advisor_recommendations(recommendations)
        first = observations[0]
        assert first.native_check_id == "242639fd-cd73-4be2-8f55-70478db8d1a5"

    def test_severity_from_impact(
        self,
        recommendations: list[dict],
    ) -> None:
        observations = parse_advisor_recommendations(recommendations)
        # First: impact "High" -> HIGH
        assert observations[0].native_severity == Severity.HIGH
        # Third: impact "Medium" -> MEDIUM
        assert observations[2].native_severity == Severity.MEDIUM
        # Fourth: impact "Low" -> LOW
        assert observations[3].native_severity == Severity.LOW

    def test_all_statuses_are_fail(
        self,
        recommendations: list[dict],
    ) -> None:
        """Azure Advisor only returns active recommendations -- all are FAIL."""
        observations = parse_advisor_recommendations(recommendations)
        for obs in observations:
            assert obs.native_status == FindingStatus.FAIL

    def test_title_from_short_description_problem(
        self,
        recommendations: list[dict],
    ) -> None:
        observations = parse_advisor_recommendations(recommendations)
        assert observations[0].title == "Create an Azure Service Health alert"

    def test_description_includes_solution(
        self,
        recommendations: list[dict],
    ) -> None:
        observations = parse_advisor_recommendations(recommendations)
        # Second recommendation has different problem and solution text
        second = observations[1]
        assert "virtual network service endpoint" in second.description

    def test_observation_id_format(
        self,
        recommendations: list[dict],
    ) -> None:
        """observation_id follows azure_advisor:{recommendationTypeId} format."""
        observations = parse_advisor_recommendations(recommendations)
        assert observations[0].observation_id == (
            "azure_advisor:242639fd-cd73-4be2-8f55-70478db8d1a5"
        )

    def test_tool_is_azure_advisor(
        self,
        recommendations: list[dict],
    ) -> None:
        observations = parse_advisor_recommendations(recommendations)
        for obs in observations:
            assert obs.tool == ToolSource.AZURE_ADVISOR

    def test_null_risk_handled_gracefully(
        self,
        recommendations: list[dict],
    ) -> None:
        """First recommendation has risk=null -- should not cause errors."""
        observations = parse_advisor_recommendations(recommendations)
        first = observations[0]
        assert first.raw_data["risk"] is None

    def test_non_null_risk_preserved_in_raw_data(
        self,
        recommendations: list[dict],
    ) -> None:
        """Second recommendation has risk="Error" -- preserved in raw_data."""
        observations = parse_advisor_recommendations(recommendations)
        second = observations[1]
        assert second.raw_data["risk"] == "Error"

    def test_empty_input(self) -> None:
        assert parse_advisor_recommendations([]) == []

    def test_benchmark_refs_empty(
        self,
        recommendations: list[dict],
    ) -> None:
        """Azure Advisor is not CIS-aligned -- no benchmark refs."""
        observations = parse_advisor_recommendations(recommendations)
        for obs in observations:
            assert obs.benchmark_refs == []

    def test_impacted_resource_in_description(
        self,
        recommendations: list[dict],
    ) -> None:
        """Description includes the impacted resource for context."""
        observations = parse_advisor_recommendations(recommendations)
        # Third recommendation targets vm-dev-01
        third = observations[2]
        assert "vm-dev-01" in third.description
