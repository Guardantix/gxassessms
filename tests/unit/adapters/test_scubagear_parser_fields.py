"""Tests for ScubaGear parser -- raw_data and benchmark_refs field extraction.

Split from test_scubagear_parser.py to stay under the 400-line limit.
Tests are written against the real fixture file (15 controls, 6 modules).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Constants (shared with test_scubagear_parser.py)
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

_FIXTURE_MODULES = {"AAD", "Defender", "EXO", "PowerPlatform", "SharePoint", "Teams"}


def _load_fixture_results() -> dict[str, list[dict[str, Any]]]:
    """Return the 'Results' dict from the ScubaResults fixture."""
    data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return data["Results"]


# ---------------------------------------------------------------------------
# raw_data contents
# ---------------------------------------------------------------------------


class TestRawData:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.scubagear.parser import parse_scuba_results

        self.parse = parse_scuba_results
        self.results = _load_fixture_results()

    def test_raw_data_contains_module_key(self) -> None:
        observations = self.parse(self.results)
        for obs in observations:
            assert "module" in obs.raw_data, f"raw_data missing 'module' for {obs.native_check_id}"

    def test_raw_data_module_is_valid_module_key(self) -> None:
        observations = self.parse(self.results)
        for obs in observations:
            assert obs.raw_data["module"] in _FIXTURE_MODULES, (
                f"Unexpected module {obs.raw_data['module']!r} for {obs.native_check_id}"
            )

    def test_raw_data_contains_group_name(self) -> None:
        observations = self.parse(self.results)
        for obs in observations:
            assert "group_name" in obs.raw_data, (
                f"raw_data missing 'group_name' for {obs.native_check_id}"
            )

    def test_raw_data_contains_group_number(self) -> None:
        observations = self.parse(self.results)
        for obs in observations:
            assert "group_number" in obs.raw_data, (
                f"raw_data missing 'group_number' for {obs.native_check_id}"
            )

    def test_raw_data_contains_details(self) -> None:
        observations = self.parse(self.results)
        for obs in observations:
            assert "details" in obs.raw_data, (
                f"raw_data missing 'details' for {obs.native_check_id}"
            )

    def test_raw_data_contains_original_result(self) -> None:
        observations = self.parse(self.results)
        for obs in observations:
            assert "original_result" in obs.raw_data, (
                f"raw_data missing 'original_result' for {obs.native_check_id}"
            )

    def test_raw_data_contains_original_details(self) -> None:
        observations = self.parse(self.results)
        for obs in observations:
            assert "original_details" in obs.raw_data, (
                f"raw_data missing 'original_details' for {obs.native_check_id}"
            )

    def test_aad_module_key_preserved(self) -> None:
        observations = self.parse(self.results)
        obs_map = {obs.native_check_id: obs for obs in observations}
        assert obs_map["MS.AAD.1.1v1"].raw_data["module"] == "AAD"

    def test_exo_module_key_preserved(self) -> None:
        observations = self.parse(self.results)
        obs_map = {obs.native_check_id: obs for obs in observations}
        assert obs_map["MS.EXO.1.1v2"].raw_data["module"] == "EXO"

    def test_teams_module_key_preserved(self) -> None:
        observations = self.parse(self.results)
        obs_map = {obs.native_check_id: obs for obs in observations}
        assert obs_map["MS.TEAMS.1.2v2"].raw_data["module"] == "Teams"

    def test_group_name_value_is_correct(self) -> None:
        observations = self.parse(self.results)
        obs_map = {obs.native_check_id: obs for obs in observations}
        assert obs_map["MS.AAD.1.1v1"].raw_data["group_name"] == "Legacy Authentication"


# ---------------------------------------------------------------------------
# benchmark_refs
# ---------------------------------------------------------------------------


class TestBenchmarkRefs:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.scubagear.parser import parse_scuba_results

        self.parse = parse_scuba_results
        self.results = _load_fixture_results()

    def test_benchmark_refs_is_list(self) -> None:
        observations = self.parse(self.results)
        for obs in observations:
            assert isinstance(obs.benchmark_refs, list), (
                f"benchmark_refs is not a list for {obs.native_check_id}"
            )

    def test_benchmark_refs_is_empty(self) -> None:
        """ScubaGear does not embed CIS refs in JSON output; list must be empty."""
        observations = self.parse(self.results)
        for obs in observations:
            assert obs.benchmark_refs == [], (
                f"benchmark_refs should be empty for {obs.native_check_id}, "
                f"got {obs.benchmark_refs!r}"
            )
