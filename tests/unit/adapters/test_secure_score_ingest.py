# tests/unit/adapters/test_secure_score_ingest.py
"""Tests for SecureScoreAdapter.ingest_from_directory."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from gxassessms.adapters.secure_score.adapter import SecureScoreAdapter
from gxassessms.core.contracts.errors import CollectionError


class TestSecureScoreIngest:
    def test_happy_path(self, tmp_path: Path) -> None:
        (tmp_path / "secureScoreControlProfiles.json").write_text('{"value": []}')
        (tmp_path / "secureScores.json").write_text('{"value": []}')
        adapter = SecureScoreAdapter()
        ts = datetime(2026, 4, 11, tzinfo=UTC)
        result = adapter.ingest_from_directory(
            tmp_path,
            schema_version="1.0.0",
            timestamp=ts,
        )
        assert len(result.artifacts) == 2
        relpaths = {a.target_relpath for a in result.artifacts}
        assert "secure-score/secureScoreControlProfiles.json" in relpaths
        assert "secure-score/secureScores.json" in relpaths
        assert result.execution_metadata == {}
        assert result.schema_version == "1.0.0"
        assert result.timestamp == ts

    def test_missing_profiles_raises(self, tmp_path: Path) -> None:
        (tmp_path / "secureScores.json").write_text('{"value": []}')
        adapter = SecureScoreAdapter()
        with pytest.raises(CollectionError, match=r"secureScoreControlProfiles\.json"):
            adapter.ingest_from_directory(
                tmp_path,
                schema_version="1.0.0",
                timestamp=datetime(2026, 4, 11, tzinfo=UTC),
            )

    def test_missing_scores_raises(self, tmp_path: Path) -> None:
        (tmp_path / "secureScoreControlProfiles.json").write_text('{"value": []}')
        adapter = SecureScoreAdapter()
        with pytest.raises(CollectionError, match=r"secureScores\.json"):
            adapter.ingest_from_directory(
                tmp_path,
                schema_version="1.0.0",
                timestamp=datetime(2026, 4, 11, tzinfo=UTC),
            )

    def test_both_files_missing_raises(self, tmp_path: Path) -> None:
        adapter = SecureScoreAdapter()
        with pytest.raises(CollectionError, match=r"secureScoreControlProfiles\.json"):
            adapter.ingest_from_directory(
                tmp_path,
                schema_version="1.0.0",
                timestamp=datetime(2026, 4, 11, tzinfo=UTC),
            )

    def test_default_schema_version_matches_collect(self) -> None:
        assert SecureScoreAdapter().default_schema_version == "1.0.0"

    def test_ingest_capability_declared(self) -> None:
        assert "ingest" in SecureScoreAdapter().capabilities

    def test_missing_source_file_raises(self, tmp_path: Path) -> None:
        """Empty source directory raises CollectionError mentioning expected filename."""
        adapter = SecureScoreAdapter()
        with pytest.raises(CollectionError, match=r"secureScoreControlProfiles\.json"):
            adapter.ingest_from_directory(
                tmp_path,
                schema_version="1.0.0",
                timestamp=datetime(2026, 4, 11, tzinfo=UTC),
            )
