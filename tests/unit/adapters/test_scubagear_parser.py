"""Tests for ScubaGear parser -- parse_scuba_results().

Tests are written against the real fixture file (see _FIXTURE_CONTROL_COUNT
and _FIXTURE_MODULES for current values).
Follows TDD: tests written first, then parser.py is implemented to pass them.

Imports of domain types are deferred into fixtures for test isolation
(same pattern as test_scubagear_mappings.py).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FIXTURE_PATH: Path = (
    Path(__file__).parents[3]
    / "src"
    / "gxassessms"
    / "adapters"
    / "scubagear"
    / "fixtures"
    / "ScubaResults.json"
)

_FIXTURE_CONTROL_COUNT = 15
_FIXTURE_MODULES = {"AAD", "Defender", "EXO", "PowerPlatform", "SharePoint", "Teams"}
_FIXTURE_STATUSES = {"Pass", "Fail", "Warning", "N/A"}
_FIXTURE_CRITICALITIES = {
    "Shall",
    "Should",
    "Shall/3rd Party",
    "Should/3rd Party",
    "Shall/Not-Implemented",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_fixture_results() -> dict[str, list[dict[str, Any]]]:
    """Return the 'Results' dict from the ScubaResults fixture."""
    data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return data["Results"]


def _first_control_in_module(
    results: dict[str, list[dict[str, Any]]], module: str
) -> dict[str, Any]:
    """Return the first control dict from the named module."""
    return results[module][0]["Controls"][0]


# ---------------------------------------------------------------------------
# Import tests
# ---------------------------------------------------------------------------


class TestImport:
    def test_parser_module_importable(self) -> None:
        from gxassessms.adapters.scubagear import parser  # noqa: F401

    def test_parse_scuba_results_exported(self) -> None:
        from gxassessms.adapters.scubagear.parser import parse_scuba_results

        assert callable(parse_scuba_results)


# ---------------------------------------------------------------------------
# Return type and count
# ---------------------------------------------------------------------------


class TestReturnType:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.scubagear.parser import parse_scuba_results
        from gxassessms.core.domain.models import ToolObservation

        self.parse = parse_scuba_results
        self.ToolObservation = ToolObservation
        self.results = _load_fixture_results()

    def test_returns_list(self) -> None:
        observations = self.parse(self.results)
        assert isinstance(observations, list)

    def test_count_matches_fixture(self) -> None:
        observations = self.parse(self.results)
        assert len(observations) == _FIXTURE_CONTROL_COUNT

    def test_all_elements_are_tool_observations(self) -> None:
        observations = self.parse(self.results)
        for obs in observations:
            assert isinstance(obs, self.ToolObservation), (
                f"Expected ToolObservation, got {type(obs)}"
            )

    def test_empty_results_returns_empty_list(self) -> None:
        observations = self.parse({})
        assert observations == []

    def test_single_control_returns_one_observation(self) -> None:
        single = {
            "AAD": [
                {
                    "GroupName": "Legacy Authentication",
                    "GroupNumber": "1",
                    "GroupReferenceURL": "https://example.com",
                    "Controls": [
                        {
                            "Control ID": "MS.AAD.1.1v1",
                            "Requirement": "Legacy authentication SHALL be blocked.",
                            "Result": "Fail",
                            "Criticality": "Shall",
                            "Details": "0 conditional access policy(s) found.",
                            "OmittedEvaluationResult": "N/A",
                            "OmittedEvaluationDetails": "N/A",
                            "IncorrectResult": "N/A",
                            "IncorrectResultDetails": "N/A",
                            "OriginalResult": "Fail",
                            "OriginalDetails": "0 conditional access policy(s) found.",
                            "Comments": [],
                            "ResolutionDate": None,
                        }
                    ],
                }
            ]
        }
        observations = self.parse(single)
        assert len(observations) == 1


# ---------------------------------------------------------------------------
# Tool source
# ---------------------------------------------------------------------------


class TestToolSource:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.scubagear.parser import parse_scuba_results
        from gxassessms.core.domain.enums import ToolSource

        self.parse = parse_scuba_results
        self.ToolSource = ToolSource
        self.results = _load_fixture_results()

    def test_all_observations_have_scubagear_tool(self) -> None:
        observations = self.parse(self.results)
        for obs in observations:
            assert obs.tool == self.ToolSource.SCUBAGEAR, (
                f"Expected SCUBAGEAR, got {obs.tool!r} for {obs.native_check_id}"
            )


# ---------------------------------------------------------------------------
# observation_id format
# ---------------------------------------------------------------------------


class TestObservationId:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.scubagear.parser import parse_scuba_results

        self.parse = parse_scuba_results
        self.results = _load_fixture_results()

    def test_observation_id_format(self) -> None:
        observations = self.parse(self.results)
        for obs in observations:
            expected = f"scubagear:{obs.native_check_id}"
            assert obs.observation_id == expected, (
                f"observation_id {obs.observation_id!r} != {expected!r}"
            )

    def test_observation_ids_are_unique(self) -> None:
        observations = self.parse(self.results)
        ids = [obs.observation_id for obs in observations]
        assert len(ids) == len(set(ids)), "Duplicate observation_ids found"


# ---------------------------------------------------------------------------
# Field extraction -- native_check_id
# ---------------------------------------------------------------------------


class TestNativeCheckId:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.scubagear.parser import parse_scuba_results

        self.parse = parse_scuba_results
        self.results = _load_fixture_results()

    def test_native_check_id_from_control_id(self) -> None:
        """native_check_id must match the 'Control ID' field exactly."""
        observations = self.parse(self.results)
        obs_by_id = {obs.native_check_id: obs for obs in observations}
        assert "MS.AAD.1.1v1" in obs_by_id
        assert "MS.EXO.1.1v2" in obs_by_id
        assert "MS.TEAMS.1.2v2" in obs_by_id

    def test_all_fixture_control_ids_present(self) -> None:
        """Every Control ID in the fixture must appear as a native_check_id."""
        all_fixture_ids: set[str] = set()
        for groups in self.results.values():
            for group in groups:
                for ctrl in group["Controls"]:
                    all_fixture_ids.add(ctrl["Control ID"])

        observations = self.parse(self.results)
        parsed_ids = {obs.native_check_id for obs in observations}
        missing = all_fixture_ids - parsed_ids
        assert not missing, f"Control IDs not parsed: {missing!r}"


# ---------------------------------------------------------------------------
# Field extraction -- title
# ---------------------------------------------------------------------------


class TestTitle:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.scubagear.parser import parse_scuba_results

        self.parse = parse_scuba_results
        self.results = _load_fixture_results()

    def test_title_comes_from_requirement(self) -> None:
        observations = self.parse(self.results)
        obs_map = {obs.native_check_id: obs for obs in observations}
        ctrl = _first_control_in_module(self.results, "AAD")
        check_id = ctrl["Control ID"]
        assert obs_map[check_id].title == ctrl["Requirement"]

    def test_titles_are_nonempty(self) -> None:
        observations = self.parse(self.results)
        for obs in observations:
            assert obs.title, f"Empty title for {obs.native_check_id}"


# ---------------------------------------------------------------------------
# Field extraction -- native_severity
# ---------------------------------------------------------------------------


class TestNativeSeverity:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.scubagear.parser import parse_scuba_results

        self.parse = parse_scuba_results
        self.results = _load_fixture_results()

    def test_native_severity_comes_from_criticality(self) -> None:
        observations = self.parse(self.results)
        obs_map = {obs.native_check_id: obs for obs in observations}
        ctrl = _first_control_in_module(self.results, "AAD")
        check_id = ctrl["Control ID"]
        assert obs_map[check_id].native_severity == ctrl["Criticality"]

    def test_multiple_criticalities_present(self) -> None:
        observations = self.parse(self.results)
        severities = {obs.native_severity for obs in observations}
        assert "Shall" in severities
        assert "Should" in severities

    def test_third_party_criticality_preserved(self) -> None:
        observations = self.parse(self.results)
        severities = {obs.native_severity for obs in observations}
        assert "Shall/3rd Party" in severities or "Should/3rd Party" in severities

    def test_not_implemented_criticality_preserved(self) -> None:
        observations = self.parse(self.results)
        severities = {obs.native_severity for obs in observations}
        assert any("Not-Implemented" in s for s in severities)


# ---------------------------------------------------------------------------
# Field extraction -- native_status
# ---------------------------------------------------------------------------


class TestNativeStatus:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.scubagear.parser import parse_scuba_results

        self.parse = parse_scuba_results
        self.results = _load_fixture_results()

    def test_native_status_comes_from_result(self) -> None:
        observations = self.parse(self.results)
        obs_map = {obs.native_check_id: obs for obs in observations}
        ctrl = _first_control_in_module(self.results, "AAD")
        check_id = ctrl["Control ID"]
        assert obs_map[check_id].native_status == ctrl["Result"]

    def test_multiple_statuses_present(self) -> None:
        observations = self.parse(self.results)
        statuses = {obs.native_status for obs in observations}
        assert "Pass" in statuses
        assert "Fail" in statuses
        assert "Warning" in statuses
        assert "N/A" in statuses

    def test_known_fail_control_has_fail_status(self) -> None:
        observations = self.parse(self.results)
        obs_map = {obs.native_check_id: obs for obs in observations}
        # MS.AAD.1.1v1 is Fail in fixture
        assert obs_map["MS.AAD.1.1v1"].native_status == "Fail"

    def test_known_pass_control_has_pass_status(self) -> None:
        observations = self.parse(self.results)
        obs_map = {obs.native_check_id: obs for obs in observations}
        # MS.AAD.3.4v1 is Pass in fixture
        assert obs_map["MS.AAD.3.4v1"].native_status == "Pass"


# ---------------------------------------------------------------------------
# Field extraction -- description
# ---------------------------------------------------------------------------


class TestDescription:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.scubagear.parser import parse_scuba_results

        self.parse = parse_scuba_results
        self.results = _load_fixture_results()

    def test_description_comes_from_details(self) -> None:
        observations = self.parse(self.results)
        obs_map = {obs.native_check_id: obs for obs in observations}
        ctrl = _first_control_in_module(self.results, "AAD")
        check_id = ctrl["Control ID"]
        assert obs_map[check_id].description == ctrl["Details"]

    def test_descriptions_are_nonempty(self) -> None:
        observations = self.parse(self.results)
        for obs in observations:
            assert obs.description, f"Empty description for {obs.native_check_id}"
