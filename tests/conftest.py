"""Shared test fixtures for GxAssessMS."""

from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Root fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def tmp_engagement_dir(tmp_path: Path) -> Path:
    """Temporary engagement directory for tests."""
    eng_dir = tmp_path / "test-engagement-001"
    eng_dir.mkdir()
    return eng_dir
