"""Tests for NormalizationPolicy -- maps ToolObservation -> Finding."""

import logging

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
            {"requirement": "Shall", "status": "FAIL", "severity": "CRITICAL"},
            {"requirement": "Shall", "status": "WARNING", "severity": "HIGH"},
            {"requirement": "Should", "status": "FAIL", "severity": "HIGH"},
            {"requirement": "Should", "status": "WARNING", "severity": "MEDIUM"},
            {"requirement": "May", "status": "FAIL", "severity": "LOW"},
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
    """ScubaGear-style adapter-specific severity map.

    Keys use domain status values (FAIL/WARNING) because _resolve_severity() now
    normalises native_status through the status_map before lookup, so aliases
    like 'Fail', 'FAIL', or 'Failed' all resolve to 'FAIL' before the key is built.
    """
    return {
        ("Shall", "FAIL"): "CRITICAL",
        ("Shall", "WARNING"): "HIGH",
        ("Should", "FAIL"): "HIGH",
        ("Should", "WARNING"): "MEDIUM",
        ("May", "FAIL"): "LOW",
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

    def test_enum_value_fail_status_resolves_severity_via_mapped_value(
        self, sample_rules: dict
    ) -> None:
        """native_status 'FAIL' (domain enum spelling, not in status_map keys) must
        reach the default_severity_map via _mapped and return CRITICAL, not fallback MEDIUM."""
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.1.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="Test check",
            native_severity="Shall",
            native_status="FAIL",  # enum-value spelling; status_map has "Fail" not "FAIL"
            description="Test.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].severity == Severity.CRITICAL

    def test_custom_status_alias_resolves_severity_via_status_map(self, sample_rules: dict) -> None:
        """A custom status_map alias (Failed -> FAIL) must propagate into the severity lookup."""
        rules = {
            **sample_rules,
            "default_status_map": {**sample_rules["default_status_map"], "Failed": "FAIL"},
        }
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.1.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="Test check",
            native_severity="Shall",
            native_status="Failed",  # custom alias; maps to "FAIL" via status_map
            description="Test.",
        )
        policy = DefaultNormalizationPolicy(rules=rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].severity == Severity.CRITICAL

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

    def test_status_fallback_to_error_for_unmapped_native_status(self, sample_rules: dict) -> None:
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.1.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="Unknown status check",
            native_severity="Shall",
            native_status="Indeterminate",
            description="Some check.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].status == FindingStatus.ERROR

    def test_category_from_display_name_value(self, sample_rules: dict) -> None:
        rules = {**sample_rules, "default_category_map": {"aad": "Identity & Access"}}
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.1.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="Identity check",
            native_severity="Shall",
            native_status="Fail",
            description="Something.",
        )
        policy = DefaultNormalizationPolicy(rules=rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].category == Category.IDENTITY_ACCESS

    def test_category_from_monkey365_check_id(self, sample_rules: dict) -> None:
        rules = {**sample_rules, "default_category_map": {"iam": "IDENTITY_ACCESS"}}
        obs = ToolObservation(
            observation_id="monkey365:m365.iam.mfa_admins",
            tool=ToolSource.MONKEY365,
            native_check_id="m365.iam.mfa_admins",
            title="MFA for admins",
            native_severity="Should",
            native_status="Fail",
            description="MFA not enabled.",
        )
        policy = DefaultNormalizationPolicy(rules=rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].category == Category.IDENTITY_ACCESS

    def test_invalid_status_map_value_raises(self, sample_rules: dict) -> None:
        rules = {**sample_rules, "default_status_map": {"Fail": "FAILED"}}  # "FAILED" not valid
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.1.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="Test",
            native_severity="Shall",
            native_status="Fail",
            description="Test.",
        )
        policy = DefaultNormalizationPolicy(rules=rules)
        with pytest.raises(ValueError, match="default_status_map"):
            policy.normalize(
                observations=[obs],
                adapter_severity_map={},
                adapter_category_map={},
                adapter_dedup_keys={},
            )

    def test_invalid_adapter_severity_value_raises(self, sample_rules: dict) -> None:
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.1.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="Test",
            native_severity="Shall",
            native_status="Fail",
            description="Test.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        with pytest.raises(ValueError, match="Adapter severity map"):
            policy.normalize(
                observations=[obs],
                adapter_severity_map={("Shall", "FAIL"): "BADVALUE"},
                adapter_category_map={},
                adapter_dedup_keys={},
            )

    def test_invalid_dedup_key_pattern_raises(self, sample_rules: dict) -> None:
        rules = {**sample_rules, "dedup_key_fallback_pattern": "{tool}:{undefined_field}"}
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.1.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="Test",
            native_severity="Shall",
            native_status="Fail",
            description="Test.",
        )
        policy = DefaultNormalizationPolicy(rules=rules)
        with pytest.raises(ValueError, match="dedup_key_fallback_pattern"):
            policy.normalize(
                observations=[obs],
                adapter_severity_map={},
                adapter_category_map={},
                adapter_dedup_keys={},  # empty -> triggers fallback -> bad pattern
            )

    def test_empty_adapter_dedup_key_raises(self, sample_rules: dict) -> None:
        """An empty string value in adapter_dedup_keys must raise ValueError.

        An empty finding_key causes consolidation to merge unrelated observations
        into the same group, corrupting severity/status/confidence.
        """
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.1.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="Test",
            native_severity="Shall",
            native_status="Fail",
            description="Test.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        with pytest.raises(ValueError, match="empty string"):
            policy.normalize(
                observations=[obs],
                adapter_severity_map={},
                adapter_category_map={},
                adapter_dedup_keys={"MS.AAD.1.1v1": ""},
            )

    def test_invalid_fallback_severity_in_rules_raises(self, sample_rules: dict) -> None:
        """G5: Invalid fallback_severity in rules raises ValueError with message
        containing 'fallback_severity' -- exercises the new try/except added in this diff."""
        rules = {**sample_rules, "fallback_severity": "NOT_A_SEVERITY"}
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.99.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.99.1v1",
            title="Unmapped check",
            native_severity="UnknownLevel",  # will miss both maps, hit fallback
            native_status="Fail",
            description="Some check.",
        )
        policy = DefaultNormalizationPolicy(rules=rules)
        with pytest.raises(ValueError, match="fallback_severity"):
            policy.normalize(
                observations=[obs],
                adapter_severity_map={},
                adapter_category_map={},
                adapter_dedup_keys={},
            )

    def test_malformed_default_severity_map_entry_missing_key_raises(
        self, sample_rules: dict
    ) -> None:
        """G6: A default_severity_map entry missing the 'severity' key raises ValueError
        with message containing 'malformed' -- exercises the KeyError branch added in diff."""
        rules = {
            **sample_rules,
            "default_severity_map": [
                {"requirement": "Shall", "status": "FAIL"},  # missing "severity" key
            ],
        }
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.1.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="Test",
            native_severity="Shall",
            native_status="Fail",
            description="Test.",
        )
        policy = DefaultNormalizationPolicy(rules=rules)
        with pytest.raises(ValueError, match="malformed"):
            policy.normalize(
                observations=[obs],
                adapter_severity_map={},
                adapter_category_map={},
                adapter_dedup_keys={},
            )

    def test_malformed_default_severity_map_entry_missing_requirement_raises(
        self, sample_rules: dict
    ) -> None:
        """Entry missing 'requirement' key raises ValueError before reaching severity lookup."""
        rules = {
            **sample_rules,
            "default_severity_map": [
                {"status": "Fail", "severity": "HIGH"},  # missing "requirement" key
            ],
        }
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.1.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="Test",
            native_severity="Shall",
            native_status="Fail",
            description="Test.",
        )
        policy = DefaultNormalizationPolicy(rules=rules)
        with pytest.raises(ValueError, match="malformed"):
            policy.normalize(
                observations=[obs],
                adapter_severity_map={},
                adapter_category_map={},
                adapter_dedup_keys={},
            )

    def test_extract_module_prefix_ms_with_only_two_parts_returns_none(
        self, sample_rules: dict
    ) -> None:
        """G8: A ScubaGear-style check ID with only 2 dot-separated parts returns None
        from _extract_module_prefix, triggering the fallback category path."""
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD",  # only 2 parts, not >= 3
            title="Malformed check ID",
            native_severity="Shall",
            native_status="Fail",
            description="Check with malformed ID.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        # No prefix extractable -> falls back to COMPLIANCE
        assert findings[0].category == Category.COMPLIANCE

    def test_unknown_category_key_in_adapter_map_logs_warning(
        self,
        sample_rules: dict,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """G9: An unrecognized category key in the default_category_map triggers a warning
        that includes the bad key value."""
        bad_key = "TOTALLY_UNKNOWN_CAT"
        rules = {**sample_rules, "default_category_map": {"unknown": bad_key}}
        obs = ToolObservation(
            observation_id="scubagear:MS.UNKNOWN.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.UNKNOWN.1v1",
            title="Unknown category check",
            native_severity="Should",
            native_status="Fail",
            description="Something.",
        )
        policy = DefaultNormalizationPolicy(rules=rules)

        with caplog.at_level(logging.WARNING, logger="gxassessms.policy.normalization"):
            findings = policy.normalize(
                observations=[obs],
                adapter_severity_map={},
                adapter_category_map={"unknown": bad_key},
                adapter_dedup_keys={},
            )

        assert findings[0].category == Category.COMPLIANCE
        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any(bad_key in msg for msg in warning_messages), (
            "Warning must include the unrecognized category key value"
        )

    def test_extract_module_prefix_empty_string_returns_none(self, sample_rules: dict) -> None:
        """G12: An empty native_check_id extracts no prefix and falls back to COMPLIANCE.
        Tests via the public normalize() path using the fallback dedup pattern."""
        # Use a custom tool with an empty check id; if Pydantic rejects empty native_check_id
        # this test documents that boundary -- in practice the fallback pattern handles it.
        obs = ToolObservation(
            observation_id="custom:unknown",
            tool=ToolSource.CUSTOM,
            native_check_id="",
            title="Custom check with empty ID",
            native_severity="Should",
            native_status="Fail",
            description="No check ID.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].category == Category.COMPLIANCE

    def test_category_from_direct_check_id_in_adapter_map(self, sample_rules: dict) -> None:
        """MT.1003 prefix is None; full check ID in adapter_category_map is consulted."""
        obs = ToolObservation(
            observation_id="maester:MT.1003",
            tool=ToolSource.MAESTER,
            native_check_id="MT.1003",
            title="Maester check",
            native_severity="Should",
            native_status="Fail",
            description="Maester check failed.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={"MT.1003": "IDENTITY_ACCESS"},
            adapter_dedup_keys={},
        )
        assert findings[0].category == Category.IDENTITY_ACCESS

    def test_category_from_direct_check_id_in_default_map(self, sample_rules: dict) -> None:
        """MT.1003 prefix is None; full check ID in default_category_map is consulted."""
        rules = {**sample_rules, "default_category_map": {"MT.1003": "IDENTITY_ACCESS"}}
        obs = ToolObservation(
            observation_id="maester:MT.1003",
            tool=ToolSource.MAESTER,
            native_check_id="MT.1003",
            title="Maester check",
            native_severity="Should",
            native_status="Fail",
            description="Maester check failed.",
        )
        policy = DefaultNormalizationPolicy(rules=rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].category == Category.IDENTITY_ACCESS

    def test_prefix_takes_precedence_over_direct_check_id_in_adapter_map(
        self, sample_rules: dict
    ) -> None:
        """When a prefix match exists, it wins; direct check ID is not consulted."""
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.1.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="AAD check",
            native_severity="Shall",
            native_status="Fail",
            description="AAD check.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        # prefix "aad" -> COMPLIANCE; direct key -> IDENTITY_ACCESS; prefix must win
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={"aad": "COMPLIANCE", "MS.AAD.1.1v1": "IDENTITY_ACCESS"},
            adapter_dedup_keys={},
        )
        assert findings[0].category == Category.COMPLIANCE

    def test_prefix_takes_precedence_over_direct_check_id_in_default_map(
        self, sample_rules: dict
    ) -> None:
        """G4: When a prefix match exists in default_category_map, it wins over the
        direct check ID key in the same map (step 3 beats step 4)."""
        # "MS.AAD.1.1v1" extracts prefix "aad"; both "aad" and "MS.AAD.1.1v1" are in
        # the default_category_map pointing to different categories.
        rules = {
            **sample_rules,
            "default_category_map": {
                "aad": "COMPLIANCE",
                "MS.AAD.1.1v1": "IDENTITY_ACCESS",
            },
        }
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.1.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="AAD check",
            native_severity="Shall",
            native_status="Fail",
            description="AAD check.",
        )
        policy = DefaultNormalizationPolicy(rules=rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},  # empty: forces use of default_category_map
            adapter_dedup_keys={},
        )
        # prefix "aad" -> COMPLIANCE must win over direct key -> IDENTITY_ACCESS
        assert findings[0].category == Category.COMPLIANCE

    def test_passing_status_maps_to_info_severity(self, sample_rules: dict) -> None:
        """native_status='Pass' (maps via status_map to PASS domain) -> INFO severity."""
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.3.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.3.1v1",
            title="MFA check",
            native_severity="Shall",
            native_status="Pass",
            description="MFA enabled.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].severity == Severity.INFO

    def test_not_applicable_status_maps_to_info_severity(self, sample_rules: dict) -> None:
        """native_status='N/A' (maps via status_map to NOT_APPLICABLE domain) -> INFO severity."""
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.3.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.3.1v1",
            title="MFA check",
            native_severity="Shall",
            native_status="N/A",
            description="Control not applicable.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].severity == Severity.INFO

    def test_enum_value_pass_status_maps_to_info_severity(self, sample_rules: dict) -> None:
        """native_status='PASS' (direct FindingStatus enum value, not in status_map) -> INFO.

        _resolve_status accepts 'PASS' via FindingStatus('PASS') direct conversion.
        _resolve_severity must agree -- consistent treatment regardless of casing.
        """
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.3.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.3.1v1",
            title="MFA check",
            native_severity="Shall",
            native_status="PASS",  # enum value spelling, not status_map key "Pass"
            description="MFA enabled.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].severity == Severity.INFO

    def test_passing_status_check_skips_adapter_severity_map(self, sample_rules: dict) -> None:
        """Domain-status short-circuit fires before adapter severity map is consulted."""
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.3.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.3.1v1",
            title="MFA check",
            native_severity="Shall",
            native_status="Pass",
            description="MFA enabled.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        # Adapter map would map ("Shall", "Pass") to CRITICAL if consulted --
        # the domain-status guard must return INFO instead.
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={("Shall", "Pass"): "CRITICAL"},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].severity == Severity.INFO

    def test_failing_status_not_affected_by_passing_check(self, sample_rules: dict) -> None:
        """Observations with Fail status are unaffected by the passing domain-status check."""
        obs = ToolObservation(
            observation_id="scubagear:MS.AAD.3.1v1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.3.1v1",
            title="MFA check",
            native_severity="Shall",
            native_status="Fail",
            description="MFA not enabled.",
        )
        policy = DefaultNormalizationPolicy(rules=sample_rules)
        findings = policy.normalize(
            observations=[obs],
            adapter_severity_map={},
            adapter_category_map={},
            adapter_dedup_keys={},
        )
        assert findings[0].severity == Severity.CRITICAL
