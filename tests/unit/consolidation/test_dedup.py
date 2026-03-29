"""Tests for the union-find dedup engine.

The dedup engine is policy-agnostic: it groups Findings by shared dedup keys
using a union-find (disjoint set) data structure. Transitive merges are the
key behavior: if A shares a key with B, and B shares a key with C, all three
end up in the same group.
"""

from __future__ import annotations

from gxassessms.consolidation.dedup import UnionFindDedup
from gxassessms.core.domain.enums import (
    ToolSource,
)

from .conftest import make_finding


class TestUnionFindDedupBasics:
    """Basic grouping behavior."""

    def test_single_finding_one_group(self) -> None:
        finding = make_finding()
        engine = UnionFindDedup()
        groups = engine.group(findings=[finding])
        assert len(groups) == 1
        assert len(groups[0]) == 1
        assert groups[0][0] is finding

    def test_empty_findings_empty_groups(self) -> None:
        engine = UnionFindDedup()
        groups = engine.group(findings=[])
        assert groups == []

    def test_same_dedup_key_merges(self) -> None:
        f1 = make_finding(
            finding_key="cis:m365:1.1.1",
            tool=ToolSource.SCUBAGEAR,
            dedup_keys=["cis:m365:1.1.1"],
        )
        f2 = make_finding(
            finding_key="cis:m365:1.1.1",
            tool=ToolSource.MAESTER,
            dedup_keys=["cis:m365:1.1.1"],
        )
        engine = UnionFindDedup()
        groups = engine.group(findings=[f1, f2])
        assert len(groups) == 1
        assert len(groups[0]) == 2

    def test_distinct_dedup_keys_separate_groups(self) -> None:
        f1 = make_finding(
            finding_key="cis:m365:1.1.1",
            dedup_keys=["cis:m365:1.1.1"],
        )
        f2 = make_finding(
            finding_key="cis:m365:2.1.1",
            dedup_keys=["cis:m365:2.1.1"],
        )
        engine = UnionFindDedup()
        groups = engine.group(findings=[f1, f2])
        assert len(groups) == 2
        for group in groups:
            assert len(group) == 1


class TestUnionFindDedupTransitive:
    """Transitive merge behavior -- the key union-find property."""

    def test_transitive_merge_three_findings(self) -> None:
        """A shares key with B, B shares key with C -> all in one group."""
        f_a = make_finding(
            finding_key="finding-a",
            dedup_keys=["cis:m365:1.1.1"],
        )
        f_b = make_finding(
            finding_key="finding-b",
            dedup_keys=["cis:m365:1.1.1", "entra:mfa:admins"],
        )
        f_c = make_finding(
            finding_key="finding-c",
            dedup_keys=["entra:mfa:admins"],
        )
        engine = UnionFindDedup()
        groups = engine.group(findings=[f_a, f_b, f_c])
        assert len(groups) == 1
        assert len(groups[0]) == 3

    def test_transitive_chain_four_findings(self) -> None:
        """A-B linked, B-C linked, C-D linked -> all in one group."""
        f_a = make_finding(finding_key="a", dedup_keys=["key-ab"])
        f_b = make_finding(finding_key="b", dedup_keys=["key-ab", "key-bc"])
        f_c = make_finding(finding_key="c", dedup_keys=["key-bc", "key-cd"])
        f_d = make_finding(finding_key="d", dedup_keys=["key-cd"])
        engine = UnionFindDedup()
        groups = engine.group(findings=[f_a, f_b, f_c, f_d])
        assert len(groups) == 1
        assert len(groups[0]) == 4

    def test_two_separate_transitive_clusters(self) -> None:
        """Two separate clusters: {A, B} and {C, D}."""
        f_a = make_finding(finding_key="a", dedup_keys=["cluster1-key"])
        f_b = make_finding(finding_key="b", dedup_keys=["cluster1-key"])
        f_c = make_finding(finding_key="c", dedup_keys=["cluster2-key"])
        f_d = make_finding(finding_key="d", dedup_keys=["cluster2-key"])
        engine = UnionFindDedup()
        groups = engine.group(findings=[f_a, f_b, f_c, f_d])
        assert len(groups) == 2
        group_sizes = sorted(len(g) for g in groups)
        assert group_sizes == [2, 2]

    def test_late_bridge_merges_clusters(self) -> None:
        """Two separate clusters bridged by a finding with keys from both."""
        f_a = make_finding(finding_key="a", dedup_keys=["alpha"])
        f_b = make_finding(finding_key="b", dedup_keys=["alpha"])
        f_c = make_finding(finding_key="c", dedup_keys=["beta"])
        f_d = make_finding(finding_key="d", dedup_keys=["beta"])
        f_bridge = make_finding(
            finding_key="bridge",
            dedup_keys=["alpha", "beta"],
        )
        engine = UnionFindDedup()
        groups = engine.group(findings=[f_a, f_b, f_c, f_d, f_bridge])
        assert len(groups) == 1
        assert len(groups[0]) == 5


class TestUnionFindDedupMultipleKeys:
    """Findings with multiple dedup keys."""

    def test_finding_with_multiple_keys_merges_with_all(self) -> None:
        f1 = make_finding(finding_key="f1", dedup_keys=["key-a"])
        f2 = make_finding(finding_key="f2", dedup_keys=["key-b"])
        f3 = make_finding(
            finding_key="f3",
            dedup_keys=["key-a", "key-b"],
        )
        engine = UnionFindDedup()
        groups = engine.group(findings=[f1, f2, f3])
        assert len(groups) == 1
        assert len(groups[0]) == 3

    def test_overlapping_multi_key_findings(self) -> None:
        """All findings share overlapping key sets."""
        f1 = make_finding(finding_key="f1", dedup_keys=["k1", "k2"])
        f2 = make_finding(finding_key="f2", dedup_keys=["k2", "k3"])
        f3 = make_finding(finding_key="f3", dedup_keys=["k3", "k4"])
        engine = UnionFindDedup()
        groups = engine.group(findings=[f1, f2, f3])
        assert len(groups) == 1

    def test_disjoint_multi_key_findings(self) -> None:
        """Multiple keys per finding but no overlap between findings."""
        f1 = make_finding(finding_key="f1", dedup_keys=["k1", "k2"])
        f2 = make_finding(finding_key="f2", dedup_keys=["k3", "k4"])
        engine = UnionFindDedup()
        groups = engine.group(findings=[f1, f2])
        assert len(groups) == 2


class TestUnionFindDedupEdgeCases:
    """Edge cases and ordering invariants."""

    def test_duplicate_dedup_keys_within_finding(self) -> None:
        """A finding with duplicate keys in its dedup_keys list."""
        f1 = make_finding(
            finding_key="f1",
            dedup_keys=["key-a", "key-a", "key-a"],
        )
        f2 = make_finding(finding_key="f2", dedup_keys=["key-a"])
        engine = UnionFindDedup()
        groups = engine.group(findings=[f1, f2])
        assert len(groups) == 1

    def test_single_finding_multiple_keys(self) -> None:
        """One finding with many keys, all pointing to the same group."""
        f1 = make_finding(
            finding_key="only",
            dedup_keys=["k1", "k2", "k3", "k4", "k5"],
        )
        engine = UnionFindDedup()
        groups = engine.group(findings=[f1])
        assert len(groups) == 1
        assert len(groups[0]) == 1

    def test_group_membership_preserves_all_findings(self) -> None:
        """Every input finding appears in exactly one output group."""
        findings = [make_finding(finding_key=f"f{i}", dedup_keys=[f"key-{i}"]) for i in range(10)]
        engine = UnionFindDedup()
        groups = engine.group(findings=findings)
        all_grouped = [f for g in groups for f in g]
        assert len(all_grouped) == 10
        assert {id(f) for f in all_grouped} == {id(f) for f in findings}

    def test_order_independence(self) -> None:
        """Groups are the same regardless of input order."""
        f_a = make_finding(finding_key="a", dedup_keys=["shared"])
        f_b = make_finding(finding_key="b", dedup_keys=["shared"])
        f_c = make_finding(finding_key="c", dedup_keys=["other"])

        engine = UnionFindDedup()
        groups_forward = engine.group(findings=[f_a, f_b, f_c])
        groups_reverse = engine.group(findings=[f_c, f_b, f_a])

        assert len(groups_forward) == len(groups_reverse)
        sizes_fwd = sorted(len(g) for g in groups_forward)
        sizes_rev = sorted(len(g) for g in groups_reverse)
        assert sizes_fwd == sizes_rev

    def test_reusable_engine_instance(self) -> None:
        """Engine instance can be reused across multiple group() calls."""
        engine = UnionFindDedup()

        f1 = make_finding(finding_key="a", dedup_keys=["k1"])
        f2 = make_finding(finding_key="b", dedup_keys=["k1"])
        groups1 = engine.group(findings=[f1, f2])
        assert len(groups1) == 1

        f3 = make_finding(finding_key="c", dedup_keys=["k2"])
        f4 = make_finding(finding_key="d", dedup_keys=["k3"])
        groups2 = engine.group(findings=[f3, f4])
        assert len(groups2) == 2

    def test_empty_string_dedup_keys_filtered(self) -> None:
        """Empty-string dedup keys are ignored and don't cause false merges."""
        f1 = make_finding(finding_key="f1", dedup_keys=["", "key-a"])
        f2 = make_finding(finding_key="f2", dedup_keys=["", "key-b"])
        engine = UnionFindDedup()
        groups = engine.group(findings=[f1, f2])
        assert len(groups) == 2

    def test_whitespace_only_dedup_keys_leave_finding_isolated(self) -> None:
        """Findings whose dedup keys are all whitespace don't merge with others."""
        f1 = make_finding(finding_key="f1", dedup_keys=["key-a"])
        f2 = make_finding(finding_key="f2", dedup_keys=["  ", "\t"])
        engine = UnionFindDedup()
        groups = engine.group(findings=[f1, f2])
        assert len(groups) == 2
        for group in groups:
            assert len(group) == 1

    def test_whitespace_padded_keys_normalize(self) -> None:
        """Dedup keys with leading/trailing whitespace match their stripped form."""
        f1 = make_finding(finding_key="f1", dedup_keys=["cis:m365:1.1.1"])
        f2 = make_finding(finding_key="f2", dedup_keys=[" cis:m365:1.1.1 "])
        engine = UnionFindDedup()
        groups = engine.group(findings=[f1, f2])
        assert len(groups) == 1
