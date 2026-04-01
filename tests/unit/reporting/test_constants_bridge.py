"""Tests for constants bridge -- generates constants.json for Node.js renderers."""

from __future__ import annotations

import json
from pathlib import Path

from gxassessms.reporting.constants_bridge import (
    generate_constants_dict,
    generate_constants_json,
    write_constants_file,
)


class TestGenerateConstantsDict:
    def test_returns_dict(self) -> None:
        result = generate_constants_dict()
        assert isinstance(result, dict)

    def test_contains_severity_order(self) -> None:
        result = generate_constants_dict()
        assert "severity_order" in result
        sev = result["severity_order"]
        assert sev["CRITICAL"] == 4
        assert sev["HIGH"] == 3
        assert sev["MEDIUM"] == 2
        assert sev["LOW"] == 1
        assert sev["INFO"] == 0

    def test_contains_severity_colors(self) -> None:
        result = generate_constants_dict()
        assert "severity_colors" in result
        colors = result["severity_colors"]
        assert set(colors.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for color in colors.values():
            assert isinstance(color, str)
            assert len(color) > 0

    def test_contains_category_display_names(self) -> None:
        result = generate_constants_dict()
        assert "category_display_names" in result
        names = result["category_display_names"]
        assert "IDENTITY_ACCESS" in names
        assert names["IDENTITY_ACCESS"] == "Identity & Access"

    def test_contains_remediation_phase_timelines(self) -> None:
        result = generate_constants_dict()
        assert "remediation_phase_timelines" in result
        phases = result["remediation_phase_timelines"]
        assert "IMMEDIATE" in phases
        assert phases["IMMEDIATE"] == "0-30 days"
        assert "SHORT_TERM" in phases
        assert "MEDIUM_TERM" in phases
        assert "LONG_TERM" in phases

    def test_no_extra_top_level_keys(self) -> None:
        result = generate_constants_dict()
        expected_keys = {
            "severity_order",
            "severity_colors",
            "category_display_names",
            "remediation_phase_timelines",
        }
        assert set(result.keys()) == expected_keys


class TestGenerateConstantsJson:
    def test_returns_valid_json_string(self) -> None:
        result = generate_constants_json()
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_json_is_sorted_and_indented(self) -> None:
        result = generate_constants_json()
        assert "\n" in result
        assert "  " in result

    def test_round_trips_through_dict(self) -> None:
        json_str = generate_constants_json()
        parsed = json.loads(json_str)
        direct = generate_constants_dict()
        assert parsed == direct


class TestWriteConstantsFile:
    def test_writes_to_path(self, tmp_path: Path) -> None:
        output = tmp_path / "constants.json"
        write_constants_file(output)
        assert output.exists()
        content = json.loads(output.read_text())
        assert "severity_order" in content

    def test_overwrites_existing(self, tmp_path: Path) -> None:
        output = tmp_path / "constants.json"
        output.write_text('{"old": "data"}')
        write_constants_file(output)
        content = json.loads(output.read_text())
        assert "old" not in content
        assert "severity_order" in content


# -- Schema Sync Tests --------------------------------------------------------
# Verifies generated constants.json stays in sync with Python constants.
# If Python constants change (new severity, renamed category, etc.),
# these tests catch unintentional drift.


class TestConstantsSchemaSync:
    def test_severity_order_keys_match_enum(self) -> None:
        from gxassessms.core.domain.constants import SEVERITIES

        result = generate_constants_dict()
        assert set(result["severity_order"].keys()) == SEVERITIES

    def test_severity_colors_keys_match_enum(self) -> None:
        from gxassessms.core.domain.constants import SEVERITIES

        result = generate_constants_dict()
        assert set(result["severity_colors"].keys()) == SEVERITIES

    def test_category_display_names_match_constants(self) -> None:
        from gxassessms.core.domain.constants import CATEGORY_DISPLAY_NAMES

        result = generate_constants_dict()
        assert result["category_display_names"] == dict(CATEGORY_DISPLAY_NAMES)

    def test_remediation_phases_match_constants(self) -> None:
        from gxassessms.core.domain.constants import REMEDIATION_PHASE_TIMELINES

        result = generate_constants_dict()
        assert result["remediation_phase_timelines"] == dict(REMEDIATION_PHASE_TIMELINES)

    def test_json_round_trip_preserves_all_values(self) -> None:
        original = generate_constants_dict()
        round_tripped = json.loads(generate_constants_json())
        assert original == round_tripped

    def test_severity_order_values_are_ints(self) -> None:
        result = generate_constants_dict()
        for key, value in result["severity_order"].items():
            assert isinstance(value, int), (
                f"severity_order['{key}'] should be int, got {type(value)}"
            )
