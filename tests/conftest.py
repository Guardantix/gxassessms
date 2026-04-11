"""Shared test fixtures for GxAssessMS."""

import importlib.resources
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml


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


@pytest.fixture(scope="session")
def normalization_rules() -> dict[str, Any]:
    """Load the bundled normalization rules YAML from the installed package."""
    pkg = importlib.resources.files("gxassessms.policy")
    text = (pkg / "rules" / "normalization.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)  # type: ignore[no-any-return]


@pytest.fixture(scope="session")
def consolidation_rules() -> dict[str, Any]:
    """Load the bundled consolidation rules YAML from the installed package."""
    pkg = importlib.resources.files("gxassessms.policy")
    text = (pkg / "rules" / "consolidation.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)  # type: ignore[no-any-return]


@pytest.fixture
def mock_orchestrator() -> MagicMock:
    """Mock Orchestrator exposing `_artifact_manager` and `_engagement_repo`.

    These two private collaborators are the only attributes tests set up,
    so a plain MagicMock with those two sub-mocks is the right shape for
    this project -- matches the existing house pattern (no `create_autospec`
    uses in the test suite).
    """
    orch = MagicMock()
    orch._artifact_manager = MagicMock()
    orch._engagement_repo = MagicMock()
    return orch
