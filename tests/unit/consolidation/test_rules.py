"""Tests for DefaultConsolidationRule.

The rule implements ConsolidationRule Protocol: it uses the dedup engine
to form groups, selects a canonical finding_key, then delegates to
ConsolidationPolicy.merge_group() to produce a ConsolidatedFinding.
"""

from __future__ import annotations

import pytest

from gxassessms.consolidation.rules import DefaultConsolidationRule
from gxassessms.core.contracts.errors import ConsolidationError
from gxassessms.core.contracts.types import ConsolidationRule
from gxassessms.core.domain.enums import (
    Severity,
    ToolSource,
)
from gxassessms.core.domain.models import (
    ConsolidatedFinding,
)
from gxassessms.policy.consolidation import (
    DefaultConsolidationPolicy,
)

from .conftest import make_finding


@pytest.fixture
def policy(consolidation_rules: dict) -> DefaultConsolidationPolicy:
    """Default consolidation policy for testing."""
    return DefaultConsolidationPolicy(rules=consolidation_rules)


class TestDefaultConsolidationRuleProtocol:
    """Verify DefaultConsolidationRule satisfies ConsolidationRule Protocol."""

    def test_satisfies_protocol(self, policy: DefaultConsolidationPolicy) -> None:
        rule = DefaultConsolidationRule(policy=policy)
        assert isinstance(rule, ConsolidationRule)

    def test_has_consolidate_method(self, policy: DefaultConsolidationPolicy) -> None:
        rule = DefaultConsolidationRule(policy=policy)
        assert hasattr(rule, "consolidate")
        assert callable(rule.consolidate)


class TestDefaultConsolidationRuleBasic:
    """Basic consolidation behavior."""

    def test_empty_input_returns_empty(self, policy: DefaultConsolidationPolicy) -> None:
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=[])
        assert result == []

    def test_single_finding_returns_one_consolidated(
        self, policy: DefaultConsolidationPolicy
    ) -> None:
        finding = make_finding()
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=[finding])
        assert len(result) == 1
        assert isinstance(result[0], ConsolidatedFinding)

    def test_same_dedup_key_merges_into_one(self, policy: DefaultConsolidationPolicy) -> None:
        f1 = make_finding(tool=ToolSource.SCUBAGEAR, dedup_keys=["shared-key"])
        f2 = make_finding(tool=ToolSource.MAESTER, dedup_keys=["shared-key"])
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=[f1, f2])
        assert len(result) == 1
        assert result[0].confidence.corroborating_tools == 2

    def test_distinct_dedup_keys_stay_separate(self, policy: DefaultConsolidationPolicy) -> None:
        f1 = make_finding(finding_key="f1", dedup_keys=["key-a"])
        f2 = make_finding(finding_key="f2", dedup_keys=["key-b"])
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=[f1, f2])
        assert len(result) == 2


class TestDefaultConsolidationRuleTransitive:
    """Transitive dedup through the full rule."""

    def test_transitive_merge(self, policy: DefaultConsolidationPolicy) -> None:
        """A -> B -> C chain merges into one consolidated finding."""
        f_a = make_finding(finding_key="a", dedup_keys=["key-ab"])
        f_b = make_finding(
            finding_key="b",
            dedup_keys=["key-ab", "key-bc"],
        )
        f_c = make_finding(finding_key="c", dedup_keys=["key-bc"])
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=[f_a, f_b, f_c])
        assert len(result) == 1
        # All three sources must be present
        assert len(result[0].sources) == 3

    def test_bridge_finding_merges_clusters(self, policy: DefaultConsolidationPolicy) -> None:
        f1 = make_finding(finding_key="f1", dedup_keys=["alpha"])
        f2 = make_finding(finding_key="f2", dedup_keys=["alpha"])
        f3 = make_finding(finding_key="f3", dedup_keys=["beta"])
        f_bridge = make_finding(
            finding_key="bridge",
            dedup_keys=["alpha", "beta"],
        )
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=[f1, f2, f3, f_bridge])
        assert len(result) == 1

    def test_heterogeneous_finding_keys_get_canonical_key(
        self, policy: DefaultConsolidationPolicy
    ) -> None:
        """When findings with different finding_keys merge, the consolidated
        finding gets a canonical key selected from the group."""
        f_a = make_finding(
            finding_key="a",
            severity=Severity.LOW,
            dedup_keys=["shared-key"],
        )
        f_b = make_finding(
            finding_key="b",
            severity=Severity.CRITICAL,
            dedup_keys=["shared-key"],
        )
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=[f_a, f_b])
        assert len(result) == 1
        # Canonical key comes from highest-severity finding
        assert result[0].finding_key == "b"

    def test_canonical_key_alphabetical_tiebreak(self, policy: DefaultConsolidationPolicy) -> None:
        """When severity ties, the alphabetically latest finding_key wins
        (max() on string comparison)."""
        f_a = make_finding(
            finding_key="alpha",
            severity=Severity.CRITICAL,
            dedup_keys=["shared-key"],
        )
        f_b = make_finding(
            finding_key="zulu",
            severity=Severity.CRITICAL,
            dedup_keys=["shared-key"],
        )
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=[f_a, f_b])
        assert len(result) == 1
        # Same severity -> alphabetical tiebreak -> "zulu" > "alpha"
        assert result[0].finding_key == "zulu"


class TestDefaultConsolidationRuleSeverity:
    """Severity reconciliation through the full rule."""

    def test_severity_takes_highest(self, policy: DefaultConsolidationPolicy) -> None:
        f_low = make_finding(
            finding_key="f1",
            severity=Severity.LOW,
            dedup_keys=["shared"],
        )
        f_critical = make_finding(
            finding_key="f2",
            severity=Severity.CRITICAL,
            dedup_keys=["shared"],
        )
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=[f_low, f_critical])
        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL

    def test_severity_never_decreases(self, policy: DefaultConsolidationPolicy) -> None:
        """Merged severity is always >= any individual source severity."""
        f1 = make_finding(severity=Severity.HIGH, dedup_keys=["shared"])
        f2 = make_finding(severity=Severity.MEDIUM, dedup_keys=["shared"])
        f3 = make_finding(severity=Severity.CRITICAL, dedup_keys=["shared"])
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=[f1, f2, f3])
        assert result[0].severity == Severity.CRITICAL


class TestDefaultConsolidationRuleOutput:
    """Output shape and content validation."""

    def test_finding_instance_id_assigned(self, policy: DefaultConsolidationPolicy) -> None:
        finding = make_finding()
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=[finding])
        assert result[0].finding_instance_id
        assert len(result[0].finding_instance_id) > 0

    def test_sources_populated(self, policy: DefaultConsolidationPolicy) -> None:
        f1 = make_finding(
            tool=ToolSource.SCUBAGEAR,
            dedup_keys=["shared"],
            observation_id="scubagear:check1",
            native_check_id="MS.AAD.1.1v1",
        )
        f2 = make_finding(
            tool=ToolSource.MAESTER,
            dedup_keys=["shared"],
            observation_id="maester:check1",
            native_check_id="MT.1003",
        )
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=[f1, f2])
        source_tools = {s.tool for s in result[0].sources}
        assert ToolSource.SCUBAGEAR in source_tools
        assert ToolSource.MAESTER in source_tools

    def test_benchmark_refs_merged_and_deduped(self, policy: DefaultConsolidationPolicy) -> None:
        f1 = make_finding(dedup_keys=["shared"], benchmark_refs=["CIS M365 1.1.1"])
        f2 = make_finding(
            dedup_keys=["shared"],
            benchmark_refs=["CIS M365 1.1.1", "NIST AC-2"],
        )
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=[f1, f2])
        refs = result[0].benchmark_refs
        assert "CIS M365 1.1.1" in refs
        assert "NIST AC-2" in refs
        assert len(refs) == len(set(refs))

    def test_all_output_are_consolidated_findings(self, policy: DefaultConsolidationPolicy) -> None:
        findings = [make_finding(finding_key=f"f{i}", dedup_keys=[f"key-{i}"]) for i in range(5)]
        rule = DefaultConsolidationRule(policy=policy)
        result = rule.consolidate(findings=findings)
        assert len(result) == 5
        for cf in result:
            assert isinstance(cf, ConsolidatedFinding)

    def test_merge_failure_wraps_as_consolidation_error(self) -> None:
        """When policy.merge_group() raises, error is wrapped with group context."""

        class FailingPolicy:
            def consolidate(self, findings: list) -> list:
                return []

            def merge_group(self, finding_key: str, findings: list) -> None:
                raise ValueError("boom")

        rule = DefaultConsolidationRule(policy=FailingPolicy())  # type: ignore[arg-type]
        with pytest.raises(ConsolidationError, match="group 1"):
            rule.consolidate(findings=[make_finding()])
