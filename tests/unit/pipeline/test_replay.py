"""Tests for replay mode.

Replay loads persisted raw output and re-enters the pipeline
at PARSE or later stage. Tests mock the artifact storage and
adapter validation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from gxassessms.core.contracts.errors import (
    InvalidRawOutputError,
    MissingRawOutputError,
)
from gxassessms.core.contracts.types import AdapterRunStatus
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import RawToolOutput
from gxassessms.pipeline.replay import (
    ReplayEngine,
    load_raw_outputs,
    validate_raw_outputs,
)
from gxassessms.pipeline.stages import Stage

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_raw_output(tool: ToolSource = ToolSource.SCUBAGEAR) -> RawToolOutput:
    return RawToolOutput(
        tool=tool,
        schema_version="1.0.0",
        timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
        file_manifest={"TestResults.json": "utf-8"},
        execution_metadata={"exit_code": 0},
    )


# ---------------------------------------------------------------------------
# load_raw_outputs tests
# ---------------------------------------------------------------------------


class TestLoadRawOutputs:
    def test_loads_from_engagement_dir(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng-001"
        eng_dir.mkdir()
        raw_dir = eng_dir / "raw-output"
        raw_dir.mkdir()

        # Write a raw output manifest
        raw_output = _make_raw_output()
        manifest_path = raw_dir / "ScubaGear.json"
        manifest_path.write_text(raw_output.model_dump_json())

        results = load_raw_outputs(eng_dir)
        assert len(results) == 1
        assert results[0].tool == ToolSource.SCUBAGEAR

    def test_missing_raw_dir_raises(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng-002"
        eng_dir.mkdir()
        with pytest.raises(MissingRawOutputError):
            load_raw_outputs(eng_dir)

    def test_empty_raw_dir_raises(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng-003"
        eng_dir.mkdir()
        raw_dir = eng_dir / "raw-output"
        raw_dir.mkdir()
        with pytest.raises(MissingRawOutputError):
            load_raw_outputs(eng_dir)


# ---------------------------------------------------------------------------
# validate_raw_outputs tests
# ---------------------------------------------------------------------------


class TestValidateRawOutputs:
    def test_valid_output_passes(self) -> None:
        raw = _make_raw_output()
        adapter = MagicMock()
        adapter.tool_name = "ScubaGear"
        adapter.validate_raw.return_value = None
        # Should not raise
        validate_raw_outputs([raw], [adapter])
        adapter.validate_raw.assert_called_once_with(raw)

    def test_invalid_output_raises(self) -> None:
        raw = _make_raw_output()
        adapter = MagicMock()
        adapter.tool_name = "ScubaGear"
        adapter.validate_raw.side_effect = ValueError("Corrupt data")
        with pytest.raises(InvalidRawOutputError):
            validate_raw_outputs([raw], [adapter])


# ---------------------------------------------------------------------------
# ReplayEngine tests
# ---------------------------------------------------------------------------


class TestReplayEngine:
    def test_default_start_stage_is_parse(self) -> None:
        engine = ReplayEngine()
        assert engine.default_start_stage == Stage.PARSE

    def test_build_adapter_results_from_raw(self) -> None:
        raw_outputs = [_make_raw_output(ToolSource.SCUBAGEAR)]
        engine = ReplayEngine()
        results = engine.build_adapter_results(raw_outputs)
        assert len(results) == 1
        assert results[0].status == AdapterRunStatus.SUCCESS.value
        assert results[0].adapter_name == ToolSource.SCUBAGEAR.value
        assert results[0].raw_output is not None

    def test_build_adapter_results_multiple_tools(self) -> None:
        raw_outputs = [
            _make_raw_output(ToolSource.SCUBAGEAR),
            _make_raw_output(ToolSource.MAESTER),
        ]
        engine = ReplayEngine()
        results = engine.build_adapter_results(raw_outputs)
        assert len(results) == 2
        names = {r.adapter_name for r in results}
        assert names == {"ScubaGear", "Maester"}

    def test_replay_start_stage_validation(self) -> None:
        engine = ReplayEngine()
        # COLLECT is not valid for replay -- must be PARSE or later
        with pytest.raises(ValueError, match="COLLECT"):
            engine.validate_start_stage(Stage.COLLECT)

    def test_replay_parse_is_valid(self) -> None:
        engine = ReplayEngine()
        # Should not raise
        engine.validate_start_stage(Stage.PARSE)

    def test_replay_normalize_is_valid(self) -> None:
        engine = ReplayEngine()
        # Should not raise
        engine.validate_start_stage(Stage.NORMALIZE)
