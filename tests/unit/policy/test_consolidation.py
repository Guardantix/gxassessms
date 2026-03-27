"""Tests for ConsolidationPolicy -- dedup merge, severity reconciliation, confidence scoring."""

import uuid

import pytest

from gxassessms.core.domain.enums import (
    Category,
    FindingStatus,
    Severity,
    ToolSource,
)
from gxassessms.core.domain.models import (
    Finding,
)
from gxassessms.policy.consolidation import (
    ConsolidationPolicy,
    DefaultConsolidationPolicy,
)


@pytest.fixture
def sample_rules() -> dict:
    """Minimal consolidation rules for testing."""
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


def _make_finding(
    *,
    finding_key: str = "cis:m365:1.1.1",
    tool: ToolSource = ToolSource.SCUBAGEAR,
    severity: Severity = Severity.CRITICAL,
    status: FindingStatus = FindingStatus.FAIL,
    title: str = "MFA for admins",
    observation_id: str | None = None,
) -> Finding:
    if observation_id is None:
        observation_id = f"{tool.value.lower()}:{uuid.uuid4().hex[:8]}"
    return Finding(
        observation_id=observation_id,
        finding_key=finding_key,
        tool=tool,
        title=title,
        severity=severity,
        status=status,
        category=Category.IDENTITY_ACCESS,
        description=f"Finding from {tool.value}",
        dedup_keys=[finding_key],
        benchmark_refs=["CIS M365 1.1.1"],
    )


class TestConsolidationProtocol:
    def test_default_policy_satisfies_protocol(self, sample_rules: dict) -> None:
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        assert isinstance(policy, ConsolidationPolicy)


class TestDefaultConsolidationPolicy:
    def test_single_finding_consolidates(self, sample_rules: dict) -> None:
        finding = _make_finding()
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        consolidated = policy.consolidate(findings=[finding])
        assert len(consolidated) == 1
        cf = consolidated[0]
        assert cf.finding_key == "cis:m365:1.1.1"
        assert cf.severity == Severity.CRITICAL
        assert cf.status == FindingStatus.FAIL
        assert len(cf.sources) == 1

    def test_dedup_merges_by_finding_key(self, sample_rules: dict) -> None:
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR)
        f2 = _make_finding(tool=ToolSource.MAESTER)
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        consolidated = policy.consolidate(findings=[f1, f2])
        assert len(consolidated) == 1
        cf = consolidated[0]
        assert cf.confidence.corroborating_tools == 2

    def test_severity_takes_highest(self, sample_rules: dict) -> None:
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR, severity=Severity.HIGH)
        f2 = _make_finding(tool=ToolSource.MAESTER, severity=Severity.CRITICAL)
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        consolidated = policy.consolidate(findings=[f1, f2])
        assert consolidated[0].severity == Severity.CRITICAL

    def test_status_takes_highest_priority(self, sample_rules: dict) -> None:
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR)
        f1 = f1.model_copy(update={"status": FindingStatus.WARNING})
        f2 = _make_finding(tool=ToolSource.MAESTER)
        f2 = f2.model_copy(update={"status": FindingStatus.FAIL})
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        consolidated = policy.consolidate(findings=[f1, f2])
        assert consolidated[0].status == FindingStatus.FAIL

    def test_distinct_finding_keys_not_merged(self, sample_rules: dict) -> None:
        f1 = _make_finding(finding_key="cis:m365:1.1.1")
        f2 = _make_finding(finding_key="cis:m365:2.1.1")
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        consolidated = policy.consolidate(findings=[f1, f2])
        assert len(consolidated) == 2

    def test_confidence_score_computed(self, sample_rules: dict) -> None:
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR)
        f2 = _make_finding(tool=ToolSource.MAESTER)
        f3 = _make_finding(tool=ToolSource.MONKEY365)
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        consolidated = policy.consolidate(findings=[f1, f2, f3])
        cf = consolidated[0]
        assert cf.confidence.corroborating_tools == 3
        assert 0.0 <= cf.confidence.overall <= 1.0
        assert cf.confidence.provenance == "system-generated"

    def test_single_tool_lower_confidence(self, sample_rules: dict) -> None:
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR)
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        consolidated_single = policy.consolidate(findings=[f1])

        f2 = _make_finding(tool=ToolSource.SCUBAGEAR)
        f3 = _make_finding(tool=ToolSource.MAESTER)
        consolidated_multi = policy.consolidate(findings=[f2, f3])

        assert consolidated_single[0].confidence.overall < consolidated_multi[0].confidence.overall

    def test_sources_populated(self, sample_rules: dict) -> None:
        f1 = _make_finding(
            tool=ToolSource.SCUBAGEAR,
            observation_id="scubagear:MS.AAD.3.1v1",
        )
        f2 = _make_finding(
            tool=ToolSource.MAESTER,
            observation_id="maester:MT.1003",
        )
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        consolidated = policy.consolidate(findings=[f1, f2])
        cf = consolidated[0]
        assert len(cf.sources) == 2
        source_tools = {s.tool for s in cf.sources}
        assert ToolSource.SCUBAGEAR in source_tools
        assert ToolSource.MAESTER in source_tools

    def test_benchmark_refs_merged(self, sample_rules: dict) -> None:
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR)
        f1 = f1.model_copy(update={"benchmark_refs": ["CIS M365 1.1.1"]})
        f2 = _make_finding(tool=ToolSource.MAESTER)
        f2 = f2.model_copy(update={"benchmark_refs": ["CIS M365 1.1.1", "NIST AC-2"]})
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        consolidated = policy.consolidate(findings=[f1, f2])
        refs = consolidated[0].benchmark_refs
        assert "CIS M365 1.1.1" in refs
        assert "NIST AC-2" in refs
        # No duplicates
        assert len(refs) == len(set(refs))

    def test_empty_findings_returns_empty(self, sample_rules: dict) -> None:
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        consolidated = policy.consolidate(findings=[])
        assert consolidated == []

    def test_finding_instance_id_assigned(self, sample_rules: dict) -> None:
        finding = _make_finding()
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        consolidated = policy.consolidate(findings=[finding])
        assert consolidated[0].finding_instance_id
        assert len(consolidated[0].finding_instance_id) > 0
