"""Integration test: ScubaGear fixtures -> parse -> normalize -> consolidate.

Verifies the consolidation engine works with real adapter output, catching
issues that hand-crafted unit tests miss: wrong dedup key formats,
unexpected finding_key patterns, field mismatches between layers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from gxassessms.adapters.scubagear.mappings import CATEGORY_MAP, DEDUP_KEY_RULES, SEVERITY_MAP
from gxassessms.adapters.scubagear.parser import parse_scuba_results
from gxassessms.consolidation.rules import DefaultConsolidationRule
from gxassessms.core.domain.models import (
    ConsolidatedFinding,
    Finding,
    ToolObservation,
)
from gxassessms.policy.consolidation import DefaultConsolidationPolicy
from gxassessms.policy.normalization import DefaultNormalizationPolicy


@pytest.fixture
def scuba_fixture_path() -> Path:
    """Path to ScubaGear test fixture data."""
    scuba_fixtures = (
        Path(__file__).parent.parent.parent
        / "src"
        / "gxassessms"
        / "adapters"
        / "scubagear"
        / "fixtures"
    )
    if scuba_fixtures.exists():
        return scuba_fixtures
    pytest.skip("ScubaGear fixtures not found")


@pytest.fixture
def normalization_rules() -> dict[str, Any]:
    """Load normalization rules from the canonical YAML file."""
    rules_path = (
        Path(__file__).parent.parent.parent
        / "src"
        / "gxassessms"
        / "policy"
        / "rules"
        / "normalization.yaml"
    )
    if not rules_path.exists():
        pytest.skip("normalization.yaml not found")
    with open(rules_path) as f:
        return yaml.safe_load(f)  # type: ignore[no-any-return]


@pytest.fixture
def consolidation_rules() -> dict[str, Any]:
    """Load consolidation rules from the canonical YAML file."""
    rules_path = (
        Path(__file__).parent.parent.parent
        / "src"
        / "gxassessms"
        / "policy"
        / "rules"
        / "consolidation.yaml"
    )
    if not rules_path.exists():
        pytest.skip("consolidation.yaml not found")
    with open(rules_path) as f:
        return yaml.safe_load(f)  # type: ignore[no-any-return]


class TestScubaGearConsolidationRoundtrip:
    """Full pipeline from ScubaGear fixtures through consolidation."""

    def test_parse_normalize_consolidate_produces_valid_output(
        self,
        scuba_fixture_path: Path,
        normalization_rules: dict[str, Any],
        consolidation_rules: dict[str, Any],
    ) -> None:
        """Smoke test: ScubaGear fixtures -> observations -> findings -> consolidated."""
        import json

        results_file = scuba_fixture_path / "ScubaResults.json"
        if not results_file.exists():
            pytest.skip("ScubaResults.json not found in fixtures")

        raw = json.loads(results_file.read_text(encoding="utf-8"))
        results = raw.get("Results", raw)

        # Step 1: Parse
        observations = parse_scuba_results(results)
        assert len(observations) > 0, "Parser should produce observations"
        for obs in observations:
            assert isinstance(obs, ToolObservation)

        # Step 2: Normalize
        # adapter maps use enum instances -- convert to string values for the policy layer,
        # matching the same conversion that AdapterConformanceSuite uses.
        adapter_severity_map: dict[tuple[str, str], str] = {
            k: v.value if hasattr(v, "value") else v for k, v in SEVERITY_MAP.items()
        }
        adapter_category_map: dict[str, str] = {
            k: v.name if hasattr(v, "name") else v for k, v in CATEGORY_MAP.items()
        }
        adapter_dedup_keys: dict[str, str] = dict(DEDUP_KEY_RULES)

        norm_policy = DefaultNormalizationPolicy(rules=normalization_rules)
        findings = norm_policy.normalize(
            observations=observations,
            adapter_severity_map=adapter_severity_map,
            adapter_category_map=adapter_category_map,
            adapter_dedup_keys=adapter_dedup_keys,
        )
        assert len(findings) > 0, "Normalization should produce findings"
        for f in findings:
            assert isinstance(f, Finding)
            assert len(f.dedup_keys) > 0, "Every finding needs dedup keys"

        # Step 3: Consolidate
        cons_policy = DefaultConsolidationPolicy(rules=consolidation_rules)
        rule = DefaultConsolidationRule(policy=cons_policy)
        consolidated = rule.consolidate(findings=findings)

        # Verify invariants
        assert len(consolidated) > 0, "Consolidation should produce results"
        assert len(consolidated) <= len(findings), "Consolidated count <= input count"
        for cf in consolidated:
            assert isinstance(cf, ConsolidatedFinding)
            assert len(cf.sources) > 0
            assert cf.finding_key
            assert cf.finding_instance_id
            assert 0.0 <= cf.confidence.overall <= 1.0
