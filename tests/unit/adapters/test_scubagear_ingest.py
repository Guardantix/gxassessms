# tests/unit/adapters/test_scubagear_ingest.py
"""Tests for ScubaGearAdapter.ingest_from_directory."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from gxassessms.adapters.scubagear.adapter import ScubaGearAdapter
from gxassessms.core.contracts.errors import CollectionError


class TestScubaGearIngest:
    def test_happy_path(self, tmp_path: Path) -> None:
        (tmp_path / "ScubaResults.json").write_text('{"data": 1}')
        adapter = ScubaGearAdapter()
        ts = datetime(2026, 4, 11, tzinfo=UTC)
        result = adapter.ingest_from_directory(
            tmp_path,
            schema_version="1.7.1",
            timestamp=ts,
        )
        assert len(result.artifacts) == 1
        assert result.artifacts[0].target_relpath == "scubagear/ScubaResults.json"
        assert result.execution_metadata == {}
        assert result.schema_version == "1.7.1"
        assert result.timestamp == ts

    def test_no_results_file_raises(self, tmp_path: Path) -> None:
        (tmp_path / "other.txt").write_text("data")
        adapter = ScubaGearAdapter()
        with pytest.raises(CollectionError, match="No ScubaResults"):
            adapter.ingest_from_directory(
                tmp_path,
                schema_version="1.7.1",
                timestamp=datetime(2026, 4, 11, tzinfo=UTC),
            )

    def test_empty_directory_raises(self, tmp_path: Path) -> None:
        adapter = ScubaGearAdapter()
        with pytest.raises(CollectionError, match="No ScubaResults"):
            adapter.ingest_from_directory(
                tmp_path,
                schema_version="1.7.1",
                timestamp=datetime(2026, 4, 11, tzinfo=UTC),
            )

    def test_default_schema_version_matches_collect(self) -> None:
        assert ScubaGearAdapter().default_schema_version == "1.7.1"

    def test_ingest_capability_declared(self) -> None:
        assert "ingest" in ScubaGearAdapter().capabilities
