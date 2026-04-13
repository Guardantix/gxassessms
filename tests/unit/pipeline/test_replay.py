"""Tests for replay mode.

Replay loads persisted raw output and re-enters the pipeline
at PARSE or later stage. After loading, manifests pass through
confine_and_resolve() before adapter methods run.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from gxassessms.core.contracts.errors import (
    InvalidRawOutputError,
    MissingRawOutputError,
)
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import RawToolOutput
from gxassessms.pipeline.confinement import LoadedManifest
from gxassessms.pipeline.replay import (
    ReplayEngine,
    load_raw_outputs,
)
from gxassessms.pipeline.stages import Stage

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_raw_output(tool: ToolSource = ToolSource.SCUBAGEAR) -> RawToolOutput:
    from gxassessms.core.domain.models import ArtifactRecord

    slug = tool.value.lower()
    return RawToolOutput(
        tool=tool,
        tool_slug=slug,
        schema_version="1.0.0",
        manifest_version="1.0.0",
        timestamp=datetime(2026, 3, 25, 10, 0, 0, tzinfo=UTC),
        file_manifest={
            f"{slug}/TestResults.json": ArtifactRecord(
                encoding="utf-8",
                sha256="a" * 64,
            ),
        },
        execution_metadata={},
    )


# ---------------------------------------------------------------------------
# load_raw_outputs tests
# ---------------------------------------------------------------------------


class TestLoadRawOutputs:
    """Tests for load_raw_outputs (spec Section 5 + Section 6)."""

    def test_loads_from_manifests_directory(self, tmp_path: Path) -> None:
        """Reads JSON files from manifests/ subdirectory."""
        eng_dir = tmp_path / "eng-001"
        manifests_dir = eng_dir / "raw-output" / "manifests"
        manifests_dir.mkdir(parents=True)

        raw_output = _make_raw_output()
        (manifests_dir / "scubagear.json").write_text(raw_output.model_dump_json())

        results = load_raw_outputs(eng_dir)
        assert len(results) == 1
        assert isinstance(results[0], LoadedManifest)
        assert results[0].raw_output.tool == ToolSource.SCUBAGEAR
        assert results[0].source_path == manifests_dir / "scubagear.json"

    def test_missing_raw_dir_raises(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng-002"
        eng_dir.mkdir()
        with pytest.raises(MissingRawOutputError):
            load_raw_outputs(eng_dir)

    def test_missing_manifests_subdir_raises(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng-003"
        (eng_dir / "raw-output").mkdir(parents=True)
        with pytest.raises(MissingRawOutputError):
            load_raw_outputs(eng_dir)

    def test_empty_manifests_dir_raises(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng-004"
        (eng_dir / "raw-output" / "manifests").mkdir(parents=True)
        with pytest.raises(MissingRawOutputError):
            load_raw_outputs(eng_dir)

    def test_malformed_json_raises_invalid(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng-bad"
        manifests_dir = eng_dir / "raw-output" / "manifests"
        manifests_dir.mkdir(parents=True)
        (manifests_dir / "broken.json").write_text("{not valid json")
        with pytest.raises(InvalidRawOutputError, match="Malformed"):
            load_raw_outputs(eng_dir)

    def test_rejects_mixed_case_filename(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng-case"
        manifests_dir = eng_dir / "raw-output" / "manifests"
        manifests_dir.mkdir(parents=True)
        raw_output = _make_raw_output()
        (manifests_dir / "ScubaGear.json").write_text(raw_output.model_dump_json())
        with pytest.raises(InvalidRawOutputError, match="lowercase"):
            load_raw_outputs(eng_dir)

    def test_rejects_non_json_file(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng-nonjson"
        manifests_dir = eng_dir / "raw-output" / "manifests"
        manifests_dir.mkdir(parents=True)
        (manifests_dir / "scubagear.txt").write_text("not json")
        with pytest.raises(InvalidRawOutputError, match="Non-JSON"):
            load_raw_outputs(eng_dir)

    def test_rejects_subdirectory_in_manifests(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng-subdir"
        manifests_dir = eng_dir / "raw-output" / "manifests"
        manifests_dir.mkdir(parents=True)
        (manifests_dir / "nested").mkdir()
        raw_output = _make_raw_output()
        (manifests_dir / "scubagear.json").write_text(raw_output.model_dump_json())
        with pytest.raises(InvalidRawOutputError, match="subdirectory"):
            load_raw_outputs(eng_dir)

    def test_loads_multiple_manifests(self, tmp_path: Path) -> None:
        eng_dir = tmp_path / "eng-multi"
        manifests_dir = eng_dir / "raw-output" / "manifests"
        manifests_dir.mkdir(parents=True)

        for tool in [ToolSource.SCUBAGEAR, ToolSource.MAESTER]:
            raw = _make_raw_output(tool)
            slug = tool.value.lower()
            (manifests_dir / f"{slug}.json").write_text(raw.model_dump_json())

        results = load_raw_outputs(eng_dir)
        assert len(results) == 2


# ---------------------------------------------------------------------------
# ReplayEngine tests
# ---------------------------------------------------------------------------


class TestReplayEngine:
    def test_default_start_stage_is_parse(self) -> None:
        engine = ReplayEngine()
        assert engine.default_start_stage == Stage.PARSE

    def test_replay_start_stage_validation(self) -> None:
        engine = ReplayEngine()
        with pytest.raises(ValueError, match="COLLECT"):
            engine.validate_start_stage(Stage.COLLECT)

    def test_replay_parse_is_valid(self) -> None:
        engine = ReplayEngine()
        engine.validate_start_stage(Stage.PARSE)

    def test_replay_normalize_is_valid(self) -> None:
        engine = ReplayEngine()
        engine.validate_start_stage(Stage.NORMALIZE)


def test_load_1_1_0_ingested_manifest(tmp_path) -> None:
    """A 1.1.0 manifest with source_mode='ingested' loads correctly."""
    from datetime import UTC, datetime

    from gxassessms.core.domain.enums import ToolSource
    from gxassessms.core.domain.models import IngestProvenance, RawToolOutput

    export_path = str(tmp_path / "export")
    prov = IngestProvenance(
        source_path=export_path,
        ingested_at=datetime(2026, 4, 11, tzinfo=UTC),
        ingested_by="human:alice",
        replaced=False,
    )
    raw = RawToolOutput(
        tool=ToolSource.SCUBAGEAR,
        tool_slug="scubagear",
        schema_version="1.7.1",
        manifest_version="1.1.0",
        timestamp=datetime(2026, 4, 11, tzinfo=UTC),
        file_manifest={"scubagear/results.json": {"encoding": "utf-8", "sha256": "a" * 64}},
        execution_metadata={},
        source_mode="ingested",
        ingest_provenance=prov,
    )
    manifest_path = tmp_path / "scubagear.json"
    manifest_path.write_text(raw.model_dump_json(indent=2))

    reloaded = RawToolOutput.model_validate_json(manifest_path.read_text())
    assert reloaded.source_mode == "ingested"
    assert reloaded.ingest_provenance.source_path == export_path
    assert reloaded.ingest_provenance.replaced is False
