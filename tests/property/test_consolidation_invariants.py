"""Property-based tests for consolidation engine invariants.

Uses Hypothesis to verify that consolidation invariants hold for ANY valid
input, not just hand-crafted test cases. These are the four invariants from
the architecture spec (Section 11):

1. Consolidated count <= input count
2. Every input finding appears in exactly one consolidated group
3. Severity never decreases during merge (takes highest)
4. No dedup key appears in more than one consolidated finding

Ref: architecture spec Section 11 (Testing Architecture), property-based testing.
"""

from __future__ import annotations

import string
import time

from hypothesis import given, settings
from hypothesis import strategies as st

from gxassessms.consolidation.dedup import UnionFindDedup
from gxassessms.consolidation.rules import DefaultConsolidationRule
from gxassessms.core.domain.constants import SEVERITY_ORDER
from gxassessms.core.domain.enums import (
    Category,
    FindingStatus,
    Severity,
    ToolSource,
)
from gxassessms.core.domain.models import Finding
from gxassessms.policy.consolidation import DefaultConsolidationPolicy

# ---------------------------------------------------------------------------
# Hypothesis strategies for generating domain objects
# ---------------------------------------------------------------------------

_severity_strategy = st.sampled_from(list(Severity))
_status_strategy = st.sampled_from(
    [
        FindingStatus.FAIL,
        FindingStatus.PASS,
        FindingStatus.WARNING,
    ]
)
_category_strategy = st.sampled_from(list(Category))
_tool_strategy = st.sampled_from(
    [
        ToolSource.SCUBAGEAR,
        ToolSource.MAESTER,
        ToolSource.MONKEY365,
        ToolSource.PROWLER,
    ]
)

# Dedup keys: short lowercase strings to encourage overlap
_dedup_key_strategy = st.text(
    alphabet=string.ascii_lowercase + string.digits + ":-",
    min_size=3,
    max_size=15,
)

_dedup_keys_strategy = st.lists(
    _dedup_key_strategy,
    min_size=1,
    max_size=4,
    unique=True,
)

_finding_key_strategy = st.text(
    alphabet=string.ascii_lowercase + string.digits + ":-",
    min_size=3,
    max_size=20,
)


@st.composite
def finding_strategy(draw: st.DrawFn) -> Finding:
    """Generate a valid Finding with random but valid field values."""
    finding_key = draw(_finding_key_strategy)
    dedup_keys = draw(_dedup_keys_strategy)
    tool = draw(_tool_strategy)
    native_check_id = (
        f"CHECK-{draw(st.text(string.ascii_uppercase + string.digits, min_size=4, max_size=6))}"
    )
    obs_suffix = draw(st.text(string.hexdigits, min_size=6, max_size=8))
    return Finding(
        observation_id=f"{tool.value.lower()}:{obs_suffix}",
        native_check_id=native_check_id,
        finding_key=finding_key,
        tool=tool,
        title=f"Test finding {finding_key}",
        severity=draw(_severity_strategy),
        status=draw(_status_strategy),
        category=draw(_category_strategy),
        description=f"Generated finding for {finding_key}",
        dedup_keys=dedup_keys,
        benchmark_refs=[],
    )


# Strategy for a non-empty list of findings
_findings_list_strategy = st.lists(
    finding_strategy(),
    min_size=1,
    max_size=20,
)


# Shared policy rules (same as used in unit tests)
_POLICY_RULES: dict = {
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


# ---------------------------------------------------------------------------
# Dedup engine invariants
# ---------------------------------------------------------------------------


class TestDedupGroupInvariants:
    """Property-based invariants for the union-find dedup engine."""

    @given(findings=_findings_list_strategy)
    @settings(max_examples=200)
    def test_group_count_lte_input_count(self, findings: list[Finding]) -> None:
        """Invariant: number of groups <= number of input findings."""
        engine = UnionFindDedup()
        groups = engine.group(findings=findings)
        assert len(groups) <= len(findings)

    @given(findings=_findings_list_strategy)
    @settings(max_examples=200)
    def test_every_finding_in_exactly_one_group(self, findings: list[Finding]) -> None:
        """Invariant: every input finding appears in exactly one group."""
        engine = UnionFindDedup()
        groups = engine.group(findings=findings)

        grouped_ids = []
        for group in groups:
            for f in group:
                grouped_ids.append(id(f))

        input_ids = [id(f) for f in findings]
        assert sorted(grouped_ids) == sorted(input_ids)

    @given(findings=_findings_list_strategy)
    @settings(max_examples=200)
    def test_no_dedup_key_in_multiple_groups(self, findings: list[Finding]) -> None:
        """Invariant: no dedup key appears in more than one group."""
        engine = UnionFindDedup()
        groups = engine.group(findings=findings)

        for i, group_i in enumerate(groups):
            keys_i = set()
            for f in group_i:
                keys_i.update(k for k in f.dedup_keys if k.strip())
            for j, group_j in enumerate(groups):
                if i >= j:
                    continue
                keys_j = set()
                for f in group_j:
                    keys_j.update(k for k in f.dedup_keys if k.strip())
                overlap = keys_i & keys_j
                assert overlap == set(), f"Groups {i} and {j} share dedup keys: {overlap}"


# ---------------------------------------------------------------------------
# Full consolidation rule invariants
# ---------------------------------------------------------------------------


class TestConsolidationRuleInvariants:
    """Property-based invariants for the full consolidation pipeline."""

    @given(findings=_findings_list_strategy)
    @settings(max_examples=200)
    def test_consolidated_count_lte_input_count(self, findings: list[Finding]) -> None:
        """Invariant 1: consolidated count <= input count."""
        policy = DefaultConsolidationPolicy(rules=_POLICY_RULES)
        rule = DefaultConsolidationRule(policy=policy)
        consolidated = rule.consolidate(findings=findings)
        assert len(consolidated) <= len(findings)

    @given(findings=_findings_list_strategy)
    @settings(max_examples=200)
    def test_severity_never_decreases(self, findings: list[Finding]) -> None:
        """Invariant 3: severity of consolidated finding >= all source severities.

        Group-to-CF matching uses positional order (both pipelines process the
        same dedup groups in the same sequence) to avoid false mismatches when
        multiple findings share the same native_check_id.
        """
        policy = DefaultConsolidationPolicy(rules=_POLICY_RULES)
        rule = DefaultConsolidationRule(policy=policy)

        # Run dedup independently to get the same groups in the same order
        engine = UnionFindDedup()
        groups = engine.group(findings=findings)
        consolidated = rule.consolidate(findings=findings)

        # DefaultConsolidationRule produces one CF per group, in group order
        assert len(consolidated) == len(groups)
        for cf, group in zip(consolidated, groups, strict=True):
            max_input_severity = max(SEVERITY_ORDER[f.severity.value] for f in group)
            assert SEVERITY_ORDER[cf.severity.value] >= max_input_severity, (
                f"CF severity {cf.severity.value} is lower than max input "
                f"severity {max_input_severity} in group"
            )

    @given(findings=_findings_list_strategy)
    @settings(max_examples=100)
    def test_every_input_finding_traceable_via_sources(self, findings: list[Finding]) -> None:
        """Invariant 2: every input finding appears in exactly one consolidated
        finding's sources (traceable via native_check_id -> SourceEvidence.check_id).
        """
        policy = DefaultConsolidationPolicy(rules=_POLICY_RULES)
        rule = DefaultConsolidationRule(policy=policy)
        consolidated = rule.consolidate(findings=findings)

        all_source_check_ids: list[str] = []
        for cf in consolidated:
            for source in cf.sources:
                all_source_check_ids.append(source.check_id)

        input_check_ids = [f.native_check_id for f in findings]

        assert sorted(all_source_check_ids) == sorted(input_check_ids)


# ---------------------------------------------------------------------------
# Idempotency and stability
# ---------------------------------------------------------------------------


class TestConsolidationStability:
    """Stability properties: consolidation is deterministic."""

    @given(findings=_findings_list_strategy)
    @settings(max_examples=50)
    def test_deterministic_output(self, findings: list[Finding]) -> None:
        """Running consolidation twice on the same input produces
        structurally identical output."""
        policy = DefaultConsolidationPolicy(rules=_POLICY_RULES)

        rule1 = DefaultConsolidationRule(policy=policy)
        result1 = rule1.consolidate(findings=findings)

        rule2 = DefaultConsolidationRule(policy=policy)
        result2 = rule2.consolidate(findings=findings)

        assert len(result1) == len(result2)

        sevs1 = sorted(cf.severity.value for cf in result1)
        sevs2 = sorted(cf.severity.value for cf in result2)
        assert sevs1 == sevs2

        keys1 = sorted(cf.finding_key for cf in result1)
        keys2 = sorted(cf.finding_key for cf in result2)
        assert keys1 == keys2

        src_counts1 = sorted(len(cf.sources) for cf in result1)
        src_counts2 = sorted(len(cf.sources) for cf in result2)
        assert src_counts1 == src_counts2

    @given(findings=_findings_list_strategy)
    @settings(max_examples=50)
    def test_confidence_scores_in_valid_range(self, findings: list[Finding]) -> None:
        """All confidence scores are in [0.0, 1.0]."""
        policy = DefaultConsolidationPolicy(rules=_POLICY_RULES)
        rule = DefaultConsolidationRule(policy=policy)
        consolidated = rule.consolidate(findings=findings)

        for cf in consolidated:
            assert 0.0 <= cf.confidence.overall <= 1.0
            assert 0.0 <= cf.confidence.evidence_strength <= 1.0
            assert 0.0 <= cf.confidence.data_freshness <= 1.0
            assert cf.confidence.corroborating_tools >= 0


# ---------------------------------------------------------------------------
# Performance regression guard
# ---------------------------------------------------------------------------


class TestConsolidationPerformance:
    """Ensure consolidation handles realistic engagement sizes."""

    def test_thousand_findings_completes_in_reasonable_time(self) -> None:
        """1000 findings with overlapping dedup keys should consolidate
        in under 5 seconds. This is a regression guard, not a benchmark."""
        findings = []
        for i in range(1000):
            cluster_key = f"cluster-{i // 5}"
            keys = [cluster_key, f"unique-{i}"]
            if i % 50 == 0 and i > 0:
                keys.append(f"cluster-{(i // 5) - 1}")
            tool = [
                ToolSource.SCUBAGEAR,
                ToolSource.MAESTER,
                ToolSource.MONKEY365,
                ToolSource.PROWLER,
            ][i % 4]
            findings.append(
                Finding(
                    observation_id=f"{tool.value.lower()}:perf-{i:04d}",
                    native_check_id=f"CHECK-{i:04d}",
                    finding_key=f"finding-{i}",
                    tool=tool,
                    title=f"Perf test finding {i}",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.FAIL,
                    category=Category.IDENTITY_ACCESS,
                    description=f"Performance test finding {i}",
                    dedup_keys=keys,
                    benchmark_refs=[],
                )
            )

        policy = DefaultConsolidationPolicy(rules=_POLICY_RULES)
        rule = DefaultConsolidationRule(policy=policy)

        start = time.monotonic()
        consolidated = rule.consolidate(findings=findings)
        elapsed = time.monotonic() - start

        assert elapsed < 5.0, f"Consolidation took {elapsed:.2f}s for 1000 findings"
        assert len(consolidated) < len(findings)
        assert len(consolidated) > 0
