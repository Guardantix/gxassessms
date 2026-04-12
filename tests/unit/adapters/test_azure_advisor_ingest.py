# tests/unit/adapters/test_azure_advisor_ingest.py
"""Tests for AzureAdvisorAdapter.ingest_from_directory."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from gxassessms.adapters.azure_advisor.adapter import AzureAdvisorAdapter
from gxassessms.core.contracts.errors import CollectionError


class TestAzureAdvisorIngest:
    def test_happy_path(self, tmp_path: Path) -> None:
        (tmp_path / "advisor_recommendations.json").write_text('{"value": []}')
        adapter = AzureAdvisorAdapter()
        ts = datetime(2026, 4, 11, tzinfo=UTC)
        result = adapter.ingest_from_directory(
            tmp_path,
            schema_version="2025-01-01",
            timestamp=ts,
        )
        assert len(result.artifacts) == 1
        assert result.artifacts[0].target_relpath == "azure-advisor/advisor_recommendations.json"
        assert result.execution_metadata == {}
        assert result.schema_version == "2025-01-01"
        assert result.timestamp == ts

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        adapter = AzureAdvisorAdapter()
        with pytest.raises(CollectionError, match="Azure Advisor output file not found"):
            adapter.ingest_from_directory(
                tmp_path,
                schema_version="2025-01-01",
                timestamp=datetime(2026, 4, 11, tzinfo=UTC),
            )

    def test_default_schema_version_matches_collect(self) -> None:
        assert AzureAdvisorAdapter().default_schema_version == "2025-01-01"

    def test_ingest_capability_declared(self) -> None:
        assert "ingest" in AzureAdvisorAdapter().capabilities
