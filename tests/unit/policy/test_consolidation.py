"""Tests for ConsolidationPolicy -- dedup merge, severity reconciliation, confidence scoring."""

import uuid

import pytest

from gxassessms.core.contracts.errors import ConsolidationError
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
            "AI-adjusted": 0.5,
        },
    }


def _make_finding(
    *,
    finding_key: str = "cis:m365:1.1.1",
    tool: ToolSource = ToolSource.SCUBAGEAR,
    severity: Severity = Severity.CRITICAL,
    status: FindingStatus = FindingStatus.FAIL,
    title: str = "MFA for admins",
    description: str | None = None,
    observation_id: str | None = None,
    native_check_id: str = "MS.AAD.1.1v1",
) -> Finding:
    if observation_id is None:
        observation_id = f"{tool.value.lower()}:{uuid.uuid4().hex[:8]}"
    return Finding(
        observation_id=observation_id,
        native_check_id=native_check_id,
        finding_key=finding_key,
        tool=tool,
        title=title,
        severity=severity,
        status=status,
        category=Category.IDENTITY_ACCESS,
        description=description if description is not None else f"Finding from {tool.value}",
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

    def test_duplicate_descriptions_deduplicated(self, sample_rules: dict) -> None:
        f1 = _make_finding(description="Same description.")
        f2 = _make_finding(tool=ToolSource.MAESTER, description="Same description.")
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        result = policy.consolidate([f1, f2])
        assert len(result) == 1
        assert result[0].description == "Same description."

    def test_distinct_descriptions_joined(self, sample_rules: dict) -> None:
        f1 = _make_finding(description="First description.")
        f2 = _make_finding(tool=ToolSource.MAESTER, description="Second description.")
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        result = policy.consolidate([f1, f2])
        assert result[0].description == "First description. | Second description."

    def test_description_order_invariant(self, sample_rules: dict) -> None:
        """Input order of findings must not affect the merged description string."""
        f1 = _make_finding(description="Zebra issue.")
        f2 = _make_finding(tool=ToolSource.MAESTER, description="Alpha issue.")
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        result_ab = policy.consolidate([f1, f2])
        result_ba = policy.consolidate([f2, f1])
        assert result_ab[0].description == result_ba[0].description
        assert result_ab[0].description == "Alpha issue. | Zebra issue."

    def test_status_reconcile_with_empty_priority_list_raises(self, sample_rules: dict) -> None:
        """G2: Empty status_priority list produces a clear error, not a bare min() ValueError."""
        rules_empty_priority = {
            **sample_rules,
            "merge_strategy": {
                **sample_rules["merge_strategy"],
                "status_priority": [],
            },
        }
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR, status=FindingStatus.FAIL)
        f2 = _make_finding(tool=ToolSource.MAESTER, status=FindingStatus.PASS)
        policy = DefaultConsolidationPolicy(rules=rules_empty_priority)
        with pytest.raises(ValueError, match="status_priority"):
            policy.consolidate([f1, f2])

    def test_unmapped_status_tie_break_is_deterministic(self, sample_rules: dict) -> None:
        """Unmapped statuses share the fallback rank; result must be stable across input orders."""
        # Use a custom priority list that omits ERROR and MANUAL so they get fallback rank.
        rules = {
            **sample_rules,
            "merge_strategy": {
                **sample_rules["merge_strategy"],
                "status_priority": ["FAIL", "WARNING", "PASS", "N/A"],
            },
        }
        # Two findings with unmapped statuses: ERROR and MANUAL both get fallback rank.
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR, status=FindingStatus.ERROR)
        f2 = _make_finding(tool=ToolSource.MAESTER, status=FindingStatus.MANUAL)
        policy = DefaultConsolidationPolicy(rules=rules)
        result_ab = policy.consolidate([f1, f2])
        result_ba = policy.consolidate([f2, f1])
        assert result_ab[0].status == result_ba[0].status

    def test_corroboration_uses_conservative_default_when_no_tier_applies(
        self, sample_rules: dict
    ) -> None:
        """When all configured tiers exceed distinct_tools, the conservative 0.4 default
        is used instead of min(corroboration_scores), which would inflate confidence."""
        # Config only defines tiers for 2+ tools; a single-tool finding must not get 0.7.
        rules_high_tier_only = {
            **sample_rules,
            "corroboration_scores": {2: 0.7, 4: 0.95},
            "confidence_weights": {
                "evidence_strength": 0.30,
                "corroboration": 0.35,
                "data_freshness": 0.20,
                "provenance": 0.15,
            },
        }
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR)
        policy = DefaultConsolidationPolicy(rules=rules_high_tier_only)
        result = policy.consolidate([f1])
        cf = result[0]
        # distinct_tools=1; no tier <=1 exists; must use 0.4, not 0.7 (tier 2)
        # evidence_strength = min(1.0, 0.6 + 1*0.1) = 0.7
        # corroboration = 0.4 (conservative fallback)
        # data_freshness = 1.0
        # provenance_score = 0.7 (system-generated)
        # overall = 0.7*0.30 + 0.4*0.35 + 1.0*0.20 + 0.7*0.15 = 0.21+0.14+0.20+0.105 = 0.655
        assert cf.confidence.overall == pytest.approx(0.655, abs=1e-3)

    def test_confidence_computed_when_corroboration_scores_empty(self, sample_rules: dict) -> None:
        """G3: Empty corroboration_scores dict does not raise; overall confidence is
        in [0.0, 1.0] and the 0.4 fallback corroboration is used."""
        rules_no_corroboration = {
            **sample_rules,
            "corroboration_scores": {},
        }
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR)
        f2 = _make_finding(tool=ToolSource.MAESTER)
        policy = DefaultConsolidationPolicy(rules=rules_no_corroboration)
        result = policy.consolidate([f1, f2])
        assert len(result) == 1
        cf = result[0]
        assert 0.0 <= cf.confidence.overall <= 1.0
        # With empty corroboration_scores the fallback corroboration=0.4 is used.
        # evidence_strength = min(1.0, 0.6 + 2*0.1) = 0.8
        # corroboration = 0.4 (fallback)
        # data_freshness = 1.0
        # provenance_score = 0.7 (system-generated)
        # overall = 0.8*0.30 + 0.4*0.35 + 1.0*0.20 + 0.7*0.15 = 0.24+0.14+0.20+0.105 = 0.685
        assert cf.confidence.overall == pytest.approx(0.685, abs=1e-3)

    def test_corroboration_string_keys_coerced_to_int(self, sample_rules: dict) -> None:
        """YAML quoted keys (strings) must be coerced to int without error."""
        rules = {
            **sample_rules,
            "corroboration_scores": {"1": 0.4, "2": 0.7},
        }
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR)
        f2 = _make_finding(tool=ToolSource.MAESTER)
        policy = DefaultConsolidationPolicy(rules=rules)
        result = policy.consolidate([f1, f2])
        assert len(result) == 1
        # 2 tools -> tier 2 -> corroboration 0.7 (same as int-keyed config)
        assert result[0].confidence.corroborating_tools == 2

    def test_corroboration_string_values_coerced_to_float(self, sample_rules: dict) -> None:
        """YAML quoted values (strings) must be coerced to float without error."""
        rules = {
            **sample_rules,
            "corroboration_scores": {"1": "0.4", "2": "0.7"},
        }
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR)
        f2 = _make_finding(tool=ToolSource.MAESTER)
        policy = DefaultConsolidationPolicy(rules=rules)
        result = policy.consolidate([f1, f2])
        assert len(result) == 1
        assert result[0].confidence.corroborating_tools == 2

    def test_corroboration_non_numeric_entry_raises(self, sample_rules: dict) -> None:
        """A non-numeric corroboration key or value must raise ValueError."""
        rules = {
            **sample_rules,
            "corroboration_scores": {"many": 0.9},
        }
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR)
        policy = DefaultConsolidationPolicy(rules=rules)
        with pytest.raises(ValueError, match="integer"):
            policy.consolidate([f1])

    def test_corroboration_non_numeric_value_raises(self, sample_rules: dict) -> None:
        """A non-numeric corroboration score value must raise ValueError."""
        rules = {
            **sample_rules,
            "corroboration_scores": {1: "high"},
        }
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR)
        policy = DefaultConsolidationPolicy(rules=rules)
        with pytest.raises(ValueError, match="numeric"):
            policy.consolidate([f1])

    def test_category_tie_resolved_deterministically(self, sample_rules: dict) -> None:
        # Both findings have equal severity (CRITICAL). f2 has category that sorts
        # later alphabetically (IDENTITY_ACCESS > COMPLIANCE). Regardless of input
        # order, the result should always be the same (no flip-flopping).
        f1 = _make_finding(tool=ToolSource.SCUBAGEAR)
        f2 = _make_finding(tool=ToolSource.MAESTER)
        f2 = f2.model_copy(update={"category": Category.COMPLIANCE})
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        result_ab = policy.consolidate([f1, f2])
        result_ba = policy.consolidate([f2, f1])
        assert result_ab[0].category == result_ba[0].category

    def test_source_evidence_check_id_uses_native_check_id(self, sample_rules: dict) -> None:
        finding = _make_finding(
            observation_id="scubagear:run-abc123",  # synthetic ingestion ID
            native_check_id="MS.AAD.3.1v1",
        )
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        consolidated = policy.consolidate(findings=[finding])
        source = consolidated[0].sources[0]
        assert source.check_id == "MS.AAD.3.1v1"
        assert source.check_id != "scubagear:run-abc123"

    def test_finding_instance_id_unique_across_calls(self, sample_rules: dict) -> None:
        """finding_instance_id must be unique per consolidation call (engagement-scoped).

        Per spec: finding_instance_id is engagement-specific and never reused across
        engagements, even for the same finding_key.  The persistence layer handles
        within-engagement dedup via (engagement_id, finding_key).
        """
        f1 = _make_finding()
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        result1 = policy.consolidate([f1])
        result2 = policy.consolidate([f1])
        assert result1[0].finding_instance_id != result2[0].finding_instance_id

    def test_merge_group_empty_findings_raises(self, sample_rules: dict) -> None:
        """merge_group() with empty findings raises ConsolidationError."""
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        with pytest.raises(ConsolidationError, match="at least one Finding"):
            policy.merge_group("some-key", [])

    def test_reconcile_title_deterministic_with_equal_severity_and_tool(
        self, sample_rules: dict
    ) -> None:
        """Title selection must be stable when severity and tool are equal for all findings."""
        f1 = _make_finding(native_check_id="check:A", title="Title A")
        f2 = _make_finding(native_check_id="check:B", title="Title B")
        policy = DefaultConsolidationPolicy(rules=sample_rules)
        result_ab = policy.consolidate([f1, f2])
        result_ba = policy.consolidate([f2, f1])
        assert result_ab[0].title == result_ba[0].title
