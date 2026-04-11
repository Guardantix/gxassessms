"""Shared test fixtures for GxAssessMS."""

import importlib.resources
from pathlib import Path
from typing import Any

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
