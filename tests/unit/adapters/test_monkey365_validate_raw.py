"""Tests for Monkey365Adapter.validate_raw(), _find_monkey365_results_file(),
and parser RawOutputValidationError handling on malformed finding IDs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from gxassessms.core.domain.models import ArtifactRecord


def _ar(encoding: str = "utf-8") -> ArtifactRecord:
    """Shorthand ArtifactRecord for tests."""
    return ArtifactRecord(encoding=encoding, sha256="a" * 64)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FIXTURE_PATH: Path = (
    Path(__file__).parents[3]
    / "src"
    / "gxassessms"
    / "adapters"
    / "monkey365"
    / "fixtures"
    / "monkey365_sample.json"
)

_COMPLETE_FINDING: dict[str, Any] = {
    "findingInfo": {
        "id": "Monkey365-aad-test-check-00000000000000000000000000000000-abc1234567890abc",
        "title": "Test check title",
        "description": "Test check description.",
    },
    "severity": "Low",
    "statusCode": "pass",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_raw_output(
    file_manifest: dict[str, Any] | None = None,
) -> Any:
    """Build a minimal ResolvedManifest for Monkey365 testing."""
    from gxassessms.core.domain.enums import ToolSource
    from gxassessms.core.domain.models import ArtifactRecord, ResolvedManifest

    if file_manifest is None:
        file_manifest = {
            str(FIXTURE_PATH): ArtifactRecord(
                encoding="utf-8",
                sha256="a" * 64,
            ),
        }
    return ResolvedManifest(
        tool=ToolSource.MONKEY365,
        tool_slug="monkey365",
        schema_version="1.0.0",
        manifest_version="1.0.0",
        timestamp=datetime.now(UTC),
        file_manifest=file_manifest,
        execution_metadata={},
    )


# ---------------------------------------------------------------------------
# TestValidateRaw
# ---------------------------------------------------------------------------


class TestValidateRaw:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.monkey365.adapter import Monkey365Adapter
        from gxassessms.core.contracts.errors import RawOutputValidationError

        self.adapter = Monkey365Adapter()
        self.RawOutputValidationError = RawOutputValidationError

    def test_empty_manifest_raises(self) -> None:
        raw = _make_raw_output(file_manifest={})
        with pytest.raises(self.RawOutputValidationError, match="empty"):
            self.adapter.validate_raw(raw)

    def test_no_monkey365_file_raises(self) -> None:
        raw = _make_raw_output(file_manifest={"/fake/not_monkey365.html": _ar()})
        with pytest.raises(self.RawOutputValidationError, match="not found"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.monkey365.adapter.load_json_file")
    def test_non_list_json_raises(self, mock_load: Any) -> None:
        mock_load.return_value = {"key": "val"}
        raw = _make_raw_output(file_manifest={"/fake/monkey365_report.json": _ar()})
        with pytest.raises(self.RawOutputValidationError, match="Expected JSON array"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.monkey365.adapter.load_json_file")
    def test_empty_array_raises(self, mock_load: Any) -> None:
        mock_load.return_value = []
        raw = _make_raw_output(file_manifest={"/fake/monkey365_report.json": _ar()})
        with pytest.raises(self.RawOutputValidationError, match="Empty"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.monkey365.adapter.load_json_file")
    def test_non_dict_element_raises(self, mock_load: Any) -> None:
        mock_load.return_value = [None]
        raw = _make_raw_output(file_manifest={"/fake/monkey365_report.json": _ar()})
        with pytest.raises(self.RawOutputValidationError, match="must be an object"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.monkey365.adapter.load_json_file")
    def test_missing_finding_info_raises(self, mock_load: Any) -> None:
        mock_load.return_value = [{"severity": "Low", "statusCode": "pass"}]
        raw = _make_raw_output(file_manifest={"/fake/monkey365_report.json": _ar()})
        with pytest.raises(self.RawOutputValidationError, match="missing 'findingInfo'"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.monkey365.adapter.load_json_file")
    def test_finding_info_not_dict_raises(self, mock_load: Any) -> None:
        mock_load.return_value = [
            {"findingInfo": "not-a-dict", "severity": "Low", "statusCode": "pass"}
        ]
        raw = _make_raw_output(file_manifest={"/fake/monkey365_report.json": _ar()})
        with pytest.raises(self.RawOutputValidationError, match="must be an object"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.monkey365.adapter.load_json_file")
    def test_missing_status_code_raises(self, mock_load: Any) -> None:
        finding = {k: v for k, v in _COMPLETE_FINDING.items() if k != "statusCode"}
        mock_load.return_value = [finding]
        raw = _make_raw_output(file_manifest={"/fake/monkey365_report.json": _ar()})
        with pytest.raises(self.RawOutputValidationError, match="missing 'statusCode'"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.monkey365.adapter.load_json_file")
    def test_missing_finding_id_raises(self, mock_load: Any) -> None:
        finding = {
            "findingInfo": {"title": "Test", "description": "Test."},
            "severity": "Low",
            "statusCode": "pass",
        }
        mock_load.return_value = [finding]
        raw = _make_raw_output(file_manifest={"/fake/monkey365_report.json": _ar()})
        with pytest.raises(self.RawOutputValidationError, match=r"findingInfo\.id is missing"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.monkey365.adapter.load_json_file")
    def test_missing_severity_raises(self, mock_load: Any) -> None:
        finding = {k: v for k, v in _COMPLETE_FINDING.items() if k != "severity"}
        mock_load.return_value = [finding]
        raw = _make_raw_output(file_manifest={"/fake/monkey365_report.json": _ar()})
        with pytest.raises(self.RawOutputValidationError, match="missing 'severity'"):
            self.adapter.validate_raw(raw)

    @patch("gxassessms.adapters.monkey365.adapter.load_json_file")
    def test_valid_fixture_passes(self, mock_load: Any) -> None:
        import json

        mock_load.return_value = json.loads(FIXTURE_PATH.read_text())
        manifest = {str(FIXTURE_PATH): _ar()}
        raw = _make_raw_output(file_manifest=manifest)
        # Should not raise
        self.adapter.validate_raw(raw)


# ---------------------------------------------------------------------------
# TestFindMonkey365ResultsFile
# ---------------------------------------------------------------------------


class TestFindMonkey365ResultsFile:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters.monkey365.adapter import Monkey365Adapter

        self.find = Monkey365Adapter._find_monkey365_results_file

    def test_finds_matching_file(self) -> None:
        assert self.find(["p/monkey365_report.json"]) == "p/monkey365_report.json"

    def test_case_insensitive_match(self) -> None:
        assert self.find(["p/Monkey365_Report.json"]) == "p/Monkey365_Report.json"

    def test_non_matching_prefix_excluded(self) -> None:
        assert self.find(["p/results.json"]) is None

    def test_wrong_prefix_excluded(self) -> None:
        assert self.find(["p/not_monkey365.json"]) is None

    def test_empty_list_returns_none(self) -> None:
        assert self.find([]) is None

    def test_multiple_matches_returns_first(self) -> None:
        files = ["a/monkey365_report1.json", "b/monkey365_report2.json"]
        assert self.find(files) == "a/monkey365_report1.json"


# ---------------------------------------------------------------------------
# TestParserErrorHandling
# ---------------------------------------------------------------------------


class TestParserErrorHandling:
    @patch("gxassessms.adapters.monkey365.adapter.load_json_file")
    def test_malformed_finding_id_raises(self, mock_load: Any) -> None:
        """A finding that passes the validator but has a non-Monkey365-format ID
        should raise RawOutputValidationError from the parser.
        """
        from gxassessms.adapters.monkey365.adapter import Monkey365Adapter
        from gxassessms.core.contracts.errors import RawOutputValidationError

        # Valid structure (passes validator), but ID doesn't match regex format
        malformed_finding = {
            "findingInfo": {
                "id": "NotMonkey365Format-whatever",
                "title": "Test",
                "description": "Test.",
            },
            "severity": "Low",
            "statusCode": "pass",
        }
        mock_load.return_value = [malformed_finding]
        raw = _make_raw_output(file_manifest={"/fake/monkey365_report.json": _ar()})
        adapter = Monkey365Adapter()
        with pytest.raises(
            RawOutputValidationError, match="does not match expected Monkey365 format"
        ):
            adapter.parse(raw)


# ---------------------------------------------------------------------------
# TestCoverageDedup
# ---------------------------------------------------------------------------


class TestCoverageDedup:
    @patch("gxassessms.adapters.monkey365.adapter.load_json_file")
    def test_duplicate_check_ids_deduplicated(self, mock_load: Any) -> None:
        """Two findings with identical findingInfo.id produce exactly one CoverageRecord."""
        from gxassessms.adapters.monkey365.adapter import Monkey365Adapter

        mock_load.return_value = [_COMPLETE_FINDING, _COMPLETE_FINDING]
        raw = _make_raw_output(file_manifest={"/fake/monkey365_report.json": _ar()})
        adapter = Monkey365Adapter()
        records = adapter.coverage(raw)
        assert len(records) == 1
