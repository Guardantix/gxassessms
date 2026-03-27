"""Tests for NormalizationPolicy -- maps ToolObservation -> Finding."""

import pytest

from gxassessms.core.domain.enums import (
    Category,
    FindingStatus,
    Severity,
    ToolSource,
)
from gxassessms.core.domain.models import ToolObservation
from gxassessms.policy.normalization import (
    DefaultNormalizationPolicy,
    NormalizationPolicy,
)


@pytest.fixture
def sample_rules() -> dict:
    """Minimal normalization rules for testing."""
    return {
        "default_severity_map": [
            {"requirement": "Shall", "status": "Fail", "severity": "CRITICAL"},
            {"requirement": "Shall", "status": "Warning", "severity": "HIGH"},
            {"requirement": "Should", "status": "Fail", "severity": "HIGH"},
            {"requirement": "Should", "status": "Warning", "severity": "MEDIUM"},
            {"requirement": "May", "status": "Fail", "severity": "LOW"},
        ],
        "fallback_severity": "MEDIUM",
        "default_category_map": {
            "aad": "IDENTITY_ACCESS",
            "exo": "EMAIL_COLLABORATION",
            "sharepoint": "DATA_PROTECTION",
            "teams": "EMAIL_COLLABORATION",
        },
        "fallback_category": "COMPLIANCE",
        "dedup_key_fallback_pattern": "{tool}:{native_check_id}",
        "default_status_map": {
            "Fail": "FAIL",
            "Pass": "PASS",
            "Warning": "WARNING",
            "Error": "ERROR",
            "N/A": "N/A",
        },
    }


@pytest.fixture
def adapter_severity_map() -> dict:
    """ScubaGear-style adapter-specific severity map."""
    return {
        ("Shall", "Fail"): "CRITICAL",
        ("Shall", "Warning"): "HIGH",
        ("Should", "Fail"): "HIGH",
        ("Should", "Warning"): "MEDIUM",
        ("May", "Fail"): "LOW",
    }


@pytest.fixture
def adapter_category_map() -> dict:
    """ScubaGear-style adapter-specific category map."""
    return {
        "aad": "IDENTITY_ACCESS",
        "exo": "EMAIL_COLLABORATION",
        "sharepoint": "DATA_PROTECTION",
    }


@pytest.fixture
def adapter_dedup_keys() -> dict:
    """Adapter-specific dedup key mapping (native_check_id -> finding_key)."""
    return {
        "MS.AAD.3.1v1": "cis:m365:1.1.1",
        "MS.AAD.3.2v1": "cis:m365:1.1.2",
        "MS.EXO.4.1v1": "cis:m365:2.1.1",
    }


@pytest.fixture
def sample_observation() -> ToolObservation:
    return ToolObservation(
        observation_id="scubagear:MS.AAD.3.1v1",
        tool=ToolSource.SCUBAGEAR,
        native_check_id="MS.AAD.3.1v1",
        title="MFA for privileged roles",
        native_severity="Shall",
        native_status="Fail",
        description="Multi-factor authentication is not enabled for admins.",
        benchmark_refs=["CIS M365 1.1.1"],
    )


class TestNormalizationProtocol:
    def test_default_policy_satisfies_protocol(self, sample_rules: dict) -> None:
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        assert isinstance(policy, NormalizationPolicy)


class TestDefaultNormalizationPolicy:
    def test_normalize_single_observation(
        self,
        sample_rules: dict,
        adapter_severity_map: dict,
        adapter_category_map: dict,
        adapter_dedup_keys: dict,
        sample_observation: ToolObservation,
    ) -> None:
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[sample_observation],
            adapter_severity_map=adapter_severity_map,
            adapter_category_map=adapter_category_map,
            adapter_dedup_keys=adapter_dedup_keys,
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.observation_id == "scubagear:MS.AAD.3.1v1"
        assert f.finding_key == "cis:m365:1.1.1"
        assert f.severity == Severity.CRITICAL
        assert f.status == FindingStatus.FAIL
        assert f.category == Category.IDENTITY_ACCESS
        assert f.dedup_keys == ["cis:m365:1.1.1"]

    def test_severity_from_adapter_map(
        self,
        sample_rules: dict,
        adapter_severity_map: dict,
        adapter_category_map: dict,
        adapter_dedup_keys: dict,
    ) -> None:
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.3.2v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.3.2v1",
            title="MFA for all users",
            native_severity="Should",
            native_status="Fail",
            description="MFA not enabled for all users.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map=adapter_severity_map,
            adapter_category_map=adapter_category_map,
            adapter_dedup_keys=adapter_dedup_keys,
        )
        assert findings[0].severity == Severity.HIGH

    def test_fallback_severity_when_no_map_match(self, sample_rules: dict) -> None:
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.99.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.99.1v1",
            title="Unknown check",
            native_severity="UnknownLevel",
            native_status="Fail",
            description="Some check.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].severity == Severity.MEDIUM

    def test_category_from_check_id_prefix(
        self,
        sample_rules: dict,
        adapter_category_map: dict,
    ) -> None:
        obs = ToolObservation(
            observation_id="scubagear:MS.EXO.4.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.EXO.4.1v1",
            title="DKIM signing",
            native_severity="Shall",
            native_status="Fail",
            description="DKIM not configured.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map=adapter_category_map,
            adapter_dedup_keys={"MS.EXO.4.1v1": "cis:m365:2.1.1"},
        )
        assert findings[0].category == Category.EMAIL_COLLABORATION

    def test_fallback_category_when_no_map_match(self, sample_rules: dict) -> None:
        obs = ToolObservation(
            observation_id="scubagear:MS.UNKNOWN.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.UNKNOWN.1v1",
            title="Unknown category check",
            native_severity="Should",
            native_status="Fail",
            description="Something.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].category == Category.COMPLIANCE

    def test_dedup_key_from_adapter_map(
        self,
        sample_rules: dict,
        adapter_dedup_keys: dict,
        sample_observation: ToolObservation,
    ) -> None:
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[sample_observation],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys=adapter_dedup_keys,
        )
        assert findings[0].finding_key == "cis:m365:1.1.1"
        assert "cis:m365:1.1.1" in findings[0].dedup_keys

    def test_dedup_key_fallback_pattern(self, sample_rules: dict) -> None:
        obs = ToolObservation(
            observation_id="maester:MT.9999",
            tool=ToolSource.MAESTER,
            native_check_id="MT.9999",
            title="Unmapped check",
            native_severity="Should",
            native_status="Fail",
            description="No cross-reference mapping.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].finding_key == "Maester:MT.9999"

    def test_status_mapping(self, sample_rules: dict) -> None:
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.1.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="Passing check",
            native_severity="Shall",
            native_status="Pass",
            description="Check passed.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].status == FindingStatus.PASS

    def test_multiple_observations(self, sample_rules: dict, adapter_dedup_keys: dict) -> None:
        obs_list = [
            ToolObservation(
                observation_id="scubagear:MS.AAD.3.1v1",
                tool=ToolSource.SCUBAGEAR,
                native_check_id="MS.AAD.3.1v1",
                title="MFA for admins",
                native_severity="Shall",
                native_status="Fail",
                description="MFA not enabled.",
            ),
            ToolObservation(
                observation_id="scubagear:MS.EXO.4.1v1",
                tool=ToolSource.SCUBAGEAR,
                native_check_id="MS.EXO.4.1v1",
                title="DKIM",
                native_severity="Should",
                native_status="Warning",
                description="DKIM misconfigured.",
            ),
        ]
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=obs_list,
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys=adapter_dedup_keys,
        )
        assert len(findings) == 2

    def test_benchmark_refs_preserved(
        self,
        sample_rules: dict,
        sample_observation: ToolObservation,
    ) -> None:
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[sample_observation],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert "CIS M365 1.1.1" in findings[0].benchmark_refs

    def test_empty_observations_returns_empty(self, sample_rules: dict) -> None:
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings == []
