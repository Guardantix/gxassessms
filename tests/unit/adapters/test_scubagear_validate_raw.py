"""Tests for ScubaGearAdapter.validate_raw(), _find_scuba_results_file(),
and parser ParseError handling on malformed controls.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

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

_COMPLETE_CONTROL: dict[str, Any] = {
    "Control ID": "MS.TEST.1.1v1",
    "Requirement": "Test requirement.",
    "Result": "Pass",
    "Criticality": "Shall",
    "Details": "All good.",
    "OmittedEvaluationResult": "N/A",
    "OmittedEvaluationDetails": "N/A",
    "IncorrectResult": "N/A",
    "IncorrectResultDetails": "N/A",
    "OriginalResult": "Pass",
    "OriginalDetails": "All good.",
    "Comments": [],
    "ResolutionDate": None,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_raw_output(file_manifest: dict[str, str] | None = None) -> Any:
    """Build a minimal RawToolOutput for testing."""
    from gxassessms.core.domain.enums import ToolSource
    from gxassessms.core.domain.models import RawToolOutput

    return RawToolOutput(
        tool=ToolSource.SCUBAGEAR,
        schema_version="1.7.1",
        timestamp=datetime.now(UTC),
        file_manifest=file_manifest or {},
        execution_metadata={},
    )


# ---------------------------------------------------------------------------
# TestValidateRaw
# ---------------------------------------------------------------------------


class TestValidateRaw:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.scubagear.adapter import ScubaGearAdapter
        from gxassessms.core.contracts.errors import RawOutputValidationError

        self.adapter = ScubaGearAdapter()
        self.RawOutputValidationError = RawOutputValidationError

    def test_empty_manifest_raises(self) -> None:
        raw = _make_raw_output(file_manifest={})
        with pytest.raises(self.RawOutputValidationError, match="manifest is empty"):
            self.adapter.validate_raw(raw)

    def test_no_scuba_results_file_raises(self) -> None:
        raw = _make_raw_output(file_manifest={"report.html": "utf-8"})
        with pytest.raises(self.RawOutputValidationError, match="not found in manifest"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.scubagear.adapter.load_json_file")
    def test_non_dict_json_raises(self, mock_load: Any) -> None:
        mock_load.return_value = [1, 2, 3]
        raw = _make_raw_output(file_manifest={"ScubaResults.json": "utf-8"})
        with pytest.raises(self.RawOutputValidationError, match="not a dict"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.scubagear.adapter.load_json_file")
    def test_missing_results_key_raises(self, mock_load: Any) -> None:
        mock_load.return_value = {"MetaData": {}}
        raw = _make_raw_output(file_manifest={"ScubaResults.json": "utf-8"})
        with pytest.raises(self.RawOutputValidationError, match="missing required 'Results'"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.scubagear.adapter.load_json_file")
    def test_results_is_list_raises(self, mock_load: Any) -> None:
        mock_load.return_value = {"Results": [1, 2, 3]}
        raw = _make_raw_output(file_manifest={"ScubaResults.json": "utf-8"})
        with pytest.raises(self.RawOutputValidationError, match="empty or not a dict"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.scubagear.adapter.load_json_file")
    def test_results_is_none_raises(self, mock_load: Any) -> None:
        mock_load.return_value = {"Results": None}
        raw = _make_raw_output(file_manifest={"ScubaResults.json": "utf-8"})
        with pytest.raises(self.RawOutputValidationError, match="empty or not a dict"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.scubagear.adapter.load_json_file")
    def test_results_empty_dict_raises(self, mock_load: Any) -> None:
        mock_load.return_value = {"Results": {}}
        raw = _make_raw_output(file_manifest={"ScubaResults.json": "utf-8"})
        with pytest.raises(self.RawOutputValidationError, match="empty or not a dict"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.scubagear.adapter.load_json_file")
    def test_no_controls_raises(self, mock_load: Any) -> None:
        mock_load.return_value = {"Results": {"AAD": [{"GroupName": "G", "Controls": []}]}}
        raw = _make_raw_output(file_manifest={"ScubaResults.json": "utf-8"})
        with pytest.raises(self.RawOutputValidationError, match="no controls"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.scubagear.adapter.load_json_file")
    def test_module_value_not_list_raises(self, mock_load: Any) -> None:
        mock_load.return_value = {"Results": {"AAD": "not-a-list"}}
        raw = _make_raw_output(file_manifest={"ScubaResults.json": "utf-8"})
        with pytest.raises(self.RawOutputValidationError, match="not a list"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.scubagear.adapter.load_json_file")
    def test_group_not_dict_raises(self, mock_load: Any) -> None:
        mock_load.return_value = {"Results": {"AAD": ["not-a-dict"]}}
        raw = _make_raw_output(file_manifest={"ScubaResults.json": "utf-8"})
        with pytest.raises(self.RawOutputValidationError, match="not a dict"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.scubagear.adapter.load_json_file")
    def test_controls_not_list_raises(self, mock_load: Any) -> None:
        mock_load.return_value = {
            "Results": {"AAD": [{"GroupName": "G", "Controls": "not-a-list"}]}
        }
        raw = _make_raw_output(file_manifest={"ScubaResults.json": "utf-8"})
        with pytest.raises(self.RawOutputValidationError, match=r"Controls.*not a list"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.scubagear.adapter.load_json_file")
    def test_control_entry_not_dict_raises(self, mock_load: Any) -> None:
        mock_load.return_value = {
            "Results": {"AAD": [{"GroupName": "G", "Controls": ["not-a-dict"]}]}
        }
        raw = _make_raw_output(file_manifest={"ScubaResults.json": "utf-8"})
        with pytest.raises(self.RawOutputValidationError, match=r"control entry.*not a dict"):
            self.adapter.validate_raw(raw)

    def test_valid_fixture_passes(self) -> None:
        manifest = {str(FIXTURE_PATH): "utf-8"}
        raw = _make_raw_output(file_manifest=manifest)
        # Should not raise
        self.adapter.validate_raw(raw)


# ---------------------------------------------------------------------------
# TestFindScubaResultsFile
# ---------------------------------------------------------------------------


class TestFindScubaResultsFile:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.scubagear.adapter import ScubaGearAdapter

        self.find = ScubaGearAdapter._find_scuba_results_file

    def test_finds_matching_file(self) -> None:
        assert self.find(["p/ScubaResults.json"]) == "p/ScubaResults.json"

    def test_case_insensitive_match(self) -> None:
        assert self.find(["p/scubaresults.json"]) == "p/scubaresults.json"

    def test_non_matching_prefix_excluded(self) -> None:
        assert self.find(["p/TestResults.json"]) is None

    def test_wrong_prefix_excluded(self) -> None:
        assert self.find(["p/not_scubaresults.json"]) is None

    def test_empty_list_returns_none(self) -> None:
        assert self.find([]) is None

    def test_multiple_matches_returns_first(self) -> None:
        files = ["a/ScubaResults1.json", "b/ScubaResults2.json"]
        assert self.find(files) == "a/ScubaResults1.json"


# ---------------------------------------------------------------------------
# TestParserErrorHandling
# ---------------------------------------------------------------------------


class TestParserErrorHandling:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.scubagear.parser import parse_scuba_results
        from gxassessms.core.contracts.errors import ParseError

        self.parse = parse_scuba_results
        self.ParseError = ParseError

    def _make_results(self, control: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        return {
            "AAD": [
                {
                    "GroupName": "Test Group",
                    "GroupNumber": "1",
                    "GroupReferenceURL": "https://example.com",
                    "Controls": [control],
                }
            ]
        }

    def test_missing_control_id_raises_parse_error(self) -> None:
        ctrl = {k: v for k, v in _COMPLETE_CONTROL.items() if k != "Control ID"}
        with pytest.raises(self.ParseError) as exc_info:
            self.parse(self._make_results(ctrl))
        assert exc_info.value.check_id == "<unknown>"
        assert exc_info.value.adapter_name == "ScubaGear"
        assert "AAD" in str(exc_info.value)

    def test_missing_requirement_raises_parse_error(self) -> None:
        ctrl = {k: v for k, v in _COMPLETE_CONTROL.items() if k != "Requirement"}
        with pytest.raises(self.ParseError) as exc_info:
            self.parse(self._make_results(ctrl))
        assert exc_info.value.check_id == "MS.TEST.1.1v1"
        assert exc_info.value.adapter_name == "ScubaGear"

    def test_missing_criticality_raises_parse_error(self) -> None:
        ctrl = {k: v for k, v in _COMPLETE_CONTROL.items() if k != "Criticality"}
        with pytest.raises(self.ParseError) as exc_info:
            self.parse(self._make_results(ctrl))
        assert exc_info.value.adapter_name == "ScubaGear"

    def test_missing_details_raises_parse_error(self) -> None:
        ctrl = {k: v for k, v in _COMPLETE_CONTROL.items() if k != "Details"}
        with pytest.raises(self.ParseError) as exc_info:
            self.parse(self._make_results(ctrl))
        assert exc_info.value.adapter_name == "ScubaGear"

    def test_parse_error_mentions_module_key(self) -> None:
        ctrl = {k: v for k, v in _COMPLETE_CONTROL.items() if k != "Result"}
        with pytest.raises(self.ParseError, match="AAD"):
            self.parse(self._make_results(ctrl))
