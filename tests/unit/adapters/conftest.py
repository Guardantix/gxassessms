"""Shared fixtures for adapter unit tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def prowler_fixture_data() -> list[dict[str, Any]]:
    """Load the Prowler OCSF fixture data."""
    fixture_path = (
        Path(__file__).parent.parent.parent.parent
        / "src"
        / "gxassessms"
        / "adapters"
        / "prowler"
        / "fixtures"
        / "prowler_sample.json"
    )
    with open(fixture_path) as f:
        return json.load(f)
