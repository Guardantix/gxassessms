"""Shared fixtures for adapter unit tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gxassessms.core.contracts.verification import (
    ModulePolicy,
    SignerIdentity,
)


def make_test_policy() -> ModulePolicy:
    """Standard ModulePolicy for verification tests."""
    return ModulePolicy(
        module_name="TestModule",
        version_range=">=1.0.0,<2.0.0",
        allowed_signers=frozenset({SignerIdentity(subject="CN=Good", issuer="CN=Root")}),
        approved_package_hashes=frozenset({"sha256tree:v1:" + "a" * 64}),
        allow_package_hash_fallback=True,
    )


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
