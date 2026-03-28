"""Shared fixtures for consolidation tests."""

from __future__ import annotations

import uuid

import pytest

from gxassessms.core.domain.enums import (
    Category,
    FindingStatus,
    Severity,
    ToolSource,
)
from gxassessms.core.domain.models import Finding


def make_finding(
    *,
    finding_key: str = "cis:m365:1.1.1",
    tool: ToolSource = ToolSource.SCUBAGEAR,
    severity: Severity = Severity.CRITICAL,
    status: FindingStatus = FindingStatus.FAIL,
    dedup_keys: list[str] | None = None,
    observation_id: str | None = None,
    native_check_id: str | None = None,
    category: Category = Category.IDENTITY_ACCESS,
    description: str | None = None,
    benchmark_refs: list[str] | None = None,
) -> Finding:
    """Create a Finding with sensible defaults for consolidation tests.

    Generates unique observation_id and derives native_check_id from
    finding_key when not explicitly provided.
    """
    if observation_id is None:
        observation_id = f"{tool.value.lower()}:{uuid.uuid4().hex[:8]}"
    if native_check_id is None:
        native_check_id = finding_key
    if dedup_keys is None:
        dedup_keys = [finding_key]
    if benchmark_refs is None:
        benchmark_refs = ["CIS M365 1.1.1"]
    return Finding(
        observation_id=observation_id,
        native_check_id=native_check_id,
        finding_key=finding_key,
        tool=tool,
        title=f"Finding {finding_key}",
        severity=severity,
        status=status,
        category=category,
        description=description or f"Test finding from {tool.value}",
        dedup_keys=dedup_keys,
        benchmark_refs=benchmark_refs,
    )


@pytest.fixture
def consolidation_rules() -> dict:
    """Consolidation policy rules for testing."""
    return {
        "merge_strategy": {
            "severity": "highest",
            "status_priority": ["FAIL", "ERROR", "WARNING", "MANUAL", "PASS", "N/A"],
            "description": "concatenate",
            "title": "highest_severity_source",
        },
        "confidence_weights": {
            "evidence_strength": 0.30,
            "corroboration": 0.35,
            "data_freshness": 0.20,
            "provenance": 0.15,
        },
        "corroboration_scores": {
            1: 0.4,
            2: 0.7,
            3: 0.85,
            4: 0.95,
        },
        "data_freshness_thresholds": {
            "fresh": 24,
            "recent": 72,
            "aging": 168,
            "stale": 720,
        },
        "provenance_scores": {
            "human-overridden": 1.0,
            "system-generated": 0.7,
            "ai-adjusted": 0.5,
        },
    }
