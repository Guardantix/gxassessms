# tests/unit/adapters/test_build_collection_output.py
"""Tests for build_collection_output shared helper (spec Section 3.1)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from gxassessms.adapters._base import build_collection_output
from gxassessms.core.contracts.errors import CollectionError
from gxassessms.core.domain.enums import ToolSource


class TestBuildCollectionOutput:
    """Tests for the shared hashing + CollectionOutput assembly helper."""

    def test_happy_path_single_item(self, tmp_path: Path) -> None:
        f = tmp_path / "results.json"
        f.write_text('{"data": 1}')
        ts = datetime(2026, 4, 11, tzinfo=UTC)
        result = build_collection_output(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            items=[(f, "scubagear/results.json")],
            schema_version="1.7.1",
            timestamp=ts,
            execution_metadata={},
        )
        assert result.tool == ToolSource.SCUBAGEAR
        assert result.tool_slug == "scubagear"
        assert result.schema_version == "1.7.1"
        assert result.timestamp == ts
        assert len(result.artifacts) == 1
        assert result.artifacts[0].target_relpath == "scubagear/results.json"
        assert len(result.artifacts[0].sha256) == 64
        assert result.execution_metadata == {}

    def test_artifacts_sorted_by_target_relpath(self, tmp_path: Path) -> None:
        b = tmp_path / "b.json"
        a = tmp_path / "a.json"
        b.write_text("b")
        a.write_text("a")
        result = build_collection_output(
            tool=ToolSource.PROWLER,
            tool_slug="prowler",
            items=[(b, "prowler/b.json"), (a, "prowler/a.json")],
            schema_version="1.4.0",
            timestamp=datetime(2026, 4, 11, tzinfo=UTC),
            execution_metadata={},
        )
        assert result.artifacts[0].target_relpath == "prowler/a.json"
        assert result.artifacts[1].target_relpath == "prowler/b.json"

    def test_empty_items_raises(self) -> None:
        with pytest.raises(CollectionError, match="empty"):
            build_collection_output(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                items=[],
                schema_version="1.7.1",
                timestamp=datetime(2026, 4, 11, tzinfo=UTC),
                execution_metadata={},
            )

    def test_target_relpath_must_start_with_slug(self, tmp_path: Path) -> None:
        f = tmp_path / "results.json"
        f.write_text("data")
        with pytest.raises(ValueError, match="scubagear/"):
            build_collection_output(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                items=[(f, "wrong-slug/results.json")],
                schema_version="1.7.1",
                timestamp=datetime(2026, 4, 11, tzinfo=UTC),
                execution_metadata={},
            )

    def test_execution_metadata_passed_through(self, tmp_path: Path) -> None:
        f = tmp_path / "r.json"
        f.write_text("data")
        meta = {"modules": ["ExoModule"], "module_provenance": {}}
        result = build_collection_output(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            items=[(f, "scubagear/r.json")],
            schema_version="1.7.1",
            timestamp=datetime(2026, 4, 11, tzinfo=UTC),
            execution_metadata=meta,
        )
        assert result.execution_metadata == meta
