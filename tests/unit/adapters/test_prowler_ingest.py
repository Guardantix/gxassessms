# tests/unit/adapters/test_prowler_ingest.py
"""Tests for ProwlerAdapter.ingest_from_directory."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from gxassessms.adapters.prowler.adapter import ProwlerAdapter
from gxassessms.core.contracts.errors import CollectionError


class TestProwlerIngest:
    def test_happy_path(self, tmp_path: Path) -> None:
        ocsf_file = tmp_path / "ProwlerResults.ocsf.json"
        ocsf_file.write_text('[{"finding_info": {}}]')
        adapter = ProwlerAdapter()
        ts = datetime(2026, 4, 11, tzinfo=UTC)
        result = adapter.ingest_from_directory(
            tmp_path,
            schema_version="1.4.0",
            timestamp=ts,
        )
        assert len(result.artifacts) == 1
        assert result.artifacts[0].target_relpath == "prowler/ProwlerResults.ocsf.json"
        assert result.execution_metadata == {}
        assert result.schema_version == "1.4.0"
        assert result.timestamp == ts

    def test_happy_path_nested_file(self, tmp_path: Path) -> None:
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        ocsf_file = subdir / "ProwlerResults.ocsf.json"
        ocsf_file.write_text('[{"finding_info": {}}]')
        adapter = ProwlerAdapter()
        ts = datetime(2026, 4, 11, tzinfo=UTC)
        result = adapter.ingest_from_directory(
            tmp_path,
            schema_version="1.4.0",
            timestamp=ts,
        )
        assert len(result.artifacts) == 1
        assert result.artifacts[0].target_relpath == "prowler/subdir/ProwlerResults.ocsf.json"

    def test_no_ocsf_file_raises(self, tmp_path: Path) -> None:
        (tmp_path / "some_other.json").write_text("[]")
        adapter = ProwlerAdapter()
        with pytest.raises(CollectionError, match="No Prowler OCSF output"):
            adapter.ingest_from_directory(
                tmp_path,
                schema_version="1.4.0",
                timestamp=datetime(2026, 4, 11, tzinfo=UTC),
            )

    def test_empty_directory_raises(self, tmp_path: Path) -> None:
        adapter = ProwlerAdapter()
        with pytest.raises(CollectionError, match="No Prowler OCSF output"):
            adapter.ingest_from_directory(
                tmp_path,
                schema_version="1.4.0",
                timestamp=datetime(2026, 4, 11, tzinfo=UTC),
            )

    def test_default_schema_version_matches_collect(self) -> None:
        assert ProwlerAdapter().default_schema_version == "1.4.0"

    def test_ingest_capability_declared(self) -> None:
        assert "ingest" in ProwlerAdapter().capabilities
