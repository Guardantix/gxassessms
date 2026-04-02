"""Tests for Maester parser -- transforms Maester Tests JSON into ToolObservations."""

import json
from pathlib import Path
from typing import Any

import pytest

from gxassessms.adapters.maester.parser import parse_maester_tests
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import ToolObservation


@pytest.fixture
def fixture_path() -> Path:
    """Path to the Maester fixture MaesterTestResults.json."""
    return (
        Path(__file__).parent.parent.parent.parent
        / "src"
        / "gxassessms"
        / "adapters"
        / "maester"
        / "fixtures"
        / "MaesterTestResults.json"
    )


@pytest.fixture
def fixture_tests(fixture_path: Path) -> list[dict[str, Any]]:
    """Raw parsed JSON test objects from fixture."""
    with open(fixture_path) as f:
        data = json.load(f)
    return data["Tests"]


@pytest.fixture
def parsed_observations(fixture_tests: list[dict[str, Any]]) -> list[ToolObservation]:
    """Observations parsed from fixture data."""
    return parse_maester_tests(fixture_tests)


class TestParseMaesterTests:
    def test_returns_list_of_tool_observations(
        self, parsed_observations: list[ToolObservation]
    ) -> None:
        assert isinstance(parsed_observations, list)
        assert all(isinstance(o, ToolObservation) for o in parsed_observations)

    def test_returns_nonempty_list(self, parsed_observations: list[ToolObservation]) -> None:
        assert len(parsed_observations) > 0

    def test_count_matches_fixture(
        self, fixture_tests: list[dict[str, Any]], parsed_observations: list[ToolObservation]
    ) -> None:
        assert len(parsed_observations) == len(fixture_tests)

    def test_all_observations_have_maester_tool(
        self, parsed_observations: list[ToolObservation]
    ) -> None:
        for obs in parsed_observations:
            assert obs.tool == ToolSource.MAESTER

    def test_observation_id_format(self, parsed_observations: list[ToolObservation]) -> None:
        """observation_id format: maester:{native_check_id}"""
        for obs in parsed_observations:
            assert obs.observation_id.startswith("maester:")
            assert obs.observation_id == f"maester:{obs.native_check_id}"

    def test_native_check_id_from_id_field(
        self, parsed_observations: list[ToolObservation]
    ) -> None:
        """Test IDs come from the 'Id' field, using multiple formats."""
        ids = {obs.native_check_id for obs in parsed_observations}
        assert "CIS.M365.1.1.1" in ids  # CIS benchmark
        assert "CISA.MS.AAD.3.1" in ids  # CISA SCuBA
        assert "EIDSCA.AF01" in ids  # EIDSCA
        assert "MT.1001" in ids  # Maester community
        assert "ORCA.118" in ids  # ORCA

    def test_title_from_title_field(self, parsed_observations: list[ToolObservation]) -> None:
        cis = next(o for o in parsed_observations if o.native_check_id == "CIS.M365.1.1.1")
        assert "cloud-only" in cis.title.lower()
        assert len(cis.title) > 0

    def test_native_severity_from_severity(
        self, parsed_observations: list[ToolObservation]
    ) -> None:
        cisa = next(o for o in parsed_observations if o.native_check_id == "CISA.MS.AAD.3.1")
        assert cisa.native_severity == "Critical"

    def test_native_status_from_result(self, parsed_observations: list[ToolObservation]) -> None:
        cisa = next(o for o in parsed_observations if o.native_check_id == "CISA.MS.AAD.3.1")
        assert cisa.native_status == "Failed"

    def test_description_from_result_detail(
        self, parsed_observations: list[ToolObservation]
    ) -> None:
        """Description extracted from ResultDetail.TestDescription."""
        cis = next(o for o in parsed_observations if o.native_check_id == "CIS.M365.1.1.1")
        assert len(cis.description) > 0
        assert "admin" in cis.description.lower() or "cloud" in cis.description.lower()

    def test_benchmark_refs_from_tag_array(
        self, parsed_observations: list[ToolObservation]
    ) -> None:
        """Tag array provides benchmark references."""
        cis = next(o for o in parsed_observations if o.native_check_id == "CIS.M365.1.1.1")
        assert "CIS.M365.1.1.1" in cis.benchmark_refs
        assert "CIS" in cis.benchmark_refs
        assert "CIS M365 v5.0.0" in cis.benchmark_refs

    def test_raw_data_preserves_block(self, parsed_observations: list[ToolObservation]) -> None:
        cis = next(o for o in parsed_observations if o.native_check_id == "CIS.M365.1.1.1")
        assert cis.raw_data["Block"] == "CIS"

    def test_raw_data_preserves_result_detail(
        self, parsed_observations: list[ToolObservation]
    ) -> None:
        cis = next(o for o in parsed_observations if o.native_check_id == "CIS.M365.1.1.1")
        assert "ResultDetail" in cis.raw_data
        assert "TestDescription" in cis.raw_data["ResultDetail"]

    def test_all_five_statuses_preserved(self, parsed_observations: list[ToolObservation]) -> None:
        statuses = {obs.native_status for obs in parsed_observations}
        assert statuses == {"Passed", "Failed", "Skipped", "Error", "NotRun"}

    def test_error_status_preserved(self, parsed_observations: list[ToolObservation]) -> None:
        error = next(o for o in parsed_observations if o.native_check_id == "MT.1033.0")
        assert error.native_status == "Error"

    def test_notrun_status_preserved(self, parsed_observations: list[ToolObservation]) -> None:
        notrun = next(
            o for o in parsed_observations if o.native_check_id == "CISA.MS.SHAREPOINT.1.1"
        )
        assert notrun.native_status == "NotRun"

    def test_null_result_detail_handled(self, parsed_observations: list[ToolObservation]) -> None:
        """NotRun tests have ResultDetail=null; parser must handle gracefully."""
        notrun = next(
            o for o in parsed_observations if o.native_check_id == "CISA.MS.SHAREPOINT.1.1"
        )
        assert notrun.description == ""  # Empty description when ResultDetail is null


class TestParseMaesterTestsEdgeCases:
    def test_empty_tests_returns_empty_list(self) -> None:
        assert parse_maester_tests([]) == []

    def test_single_test(self) -> None:
        single = [
            {
                "Index": 1,
                "Id": "MT.9999",
                "Title": "Test check",
                "Name": "MT.9999: Test check",
                "HelpUrl": "",
                "Severity": "High",
                "Tag": ["MT.9999", "CA"],
                "Result": "Failed",
                "ScriptBlock": "",
                "ScriptBlockFile": "",
                "ErrorRecord": [],
                "Block": "Maester/Entra",
                "Duration": "00:00:00",
                "ResultDetail": {
                    "Service": None,
                    "SkippedReason": None,
                    "TestInvestigate": False,
                    "TestDescription": "Test description",
                    "TestTitle": "MT.9999: Test check",
                    "Severity": "",
                    "TestResult": "Test failed.",
                    "TestSkipped": "",
                },
            }
        ]
        observations = parse_maester_tests(single)
        assert len(observations) == 1
        assert observations[0].native_check_id == "MT.9999"
        assert observations[0].native_status == "Failed"
