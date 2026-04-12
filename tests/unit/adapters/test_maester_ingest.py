# tests/unit/adapters/test_maester_ingest.py
"""Tests for MaesterAdapter.ingest_from_directory."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from gxassessms.adapters.maester.adapter import MaesterAdapter
from gxassessms.core.contracts.errors import CollectionError


class TestMaesterIngest:
    def test_happy_path(self, tmp_path: Path) -> None:
        (tmp_path / "TestResults-20260411T120000.json").write_text('{"Tests": []}')
        adapter = MaesterAdapter()
        ts = datetime(2026, 4, 11, tzinfo=UTC)
        result = adapter.ingest_from_directory(
            tmp_path,
            schema_version="1.0.0",
            timestamp=ts,
        )
        assert len(result.artifacts) == 1
        assert result.artifacts[0].target_relpath == "maester/TestResults-20260411T120000.json"
        assert result.execution_metadata == {}
        assert result.schema_version == "1.0.0"
        assert result.timestamp == ts

    def test_no_results_file_raises(self, tmp_path: Path) -> None:
        adapter = MaesterAdapter()
        with pytest.raises(CollectionError, match="No TestResults"):
            adapter.ingest_from_directory(
                tmp_path,
                schema_version="1.0.0",
                timestamp=datetime(2026, 4, 11, tzinfo=UTC),
            )

    def test_multiple_results_files_raises(self, tmp_path: Path) -> None:
        (tmp_path / "TestResults-001.json").write_text('{"Tests": []}')
        (tmp_path / "TestResults-002.json").write_text('{"Tests": []}')
        adapter = MaesterAdapter()
        with pytest.raises(CollectionError, match="Expected exactly 1"):
            adapter.ingest_from_directory(
                tmp_path,
                schema_version="1.0.0",
                timestamp=datetime(2026, 4, 11, tzinfo=UTC),
            )

    def test_default_schema_version_matches_collect(self) -> None:
        assert MaesterAdapter().default_schema_version == "1.0.0"

    def test_ingest_capability_declared(self) -> None:
        assert "ingest" in MaesterAdapter().capabilities
