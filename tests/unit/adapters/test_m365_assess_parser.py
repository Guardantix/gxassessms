"""Tests for M365-Assess CSV parser."""

from pathlib import Path

import pytest

from gxassessms.adapters.m365_assess.parser import (
    load_registry,
    load_risk_severity,
    parse_security_config_csv,
)
from gxassessms.core.domain.enums import FindingStatus, ToolSource
from gxassessms.core.domain.models import ToolObservation

FIXTURE_DIR = (
    Path(__file__).parent.parent.parent.parent
    / "src"
    / "gxassessms"
    / "adapters"
    / "m365_assess"
    / "fixtures"
)


@pytest.fixture
def severity_map() -> dict[str, str]:
    return load_risk_severity(FIXTURE_DIR / "risk_severity_sample.json")


@pytest.fixture
def registry() -> dict[str, dict]:
    return load_registry(FIXTURE_DIR / "registry_sample.json")


class TestLoadRiskSeverity:
    def test_returns_dict(self) -> None:
        result = load_risk_severity(FIXTURE_DIR / "risk_severity_sample.json")
        assert isinstance(result, dict)

    def test_keys_are_base_check_ids(self) -> None:
        result = load_risk_severity(FIXTURE_DIR / "risk_severity_sample.json")
        assert "ENTRA-ADMIN-001" in result
        assert "EXO-AUTH-001" in result

    def test_values_are_severity_strings(self) -> None:
        result = load_risk_severity(FIXTURE_DIR / "risk_severity_sample.json")
        assert result["ENTRA-ADMIN-001"] == "High"
        assert result["ENTRA-PERUSER-001"] == "Critical"

    def test_raises_on_non_dict_checks(self, tmp_path: Path) -> None:
        """risk-severity.json with 'checks' as a non-dict must raise RawOutputValidationError."""
        import json

        from gxassessms.core.contracts.errors import RawOutputValidationError

        bad_severity = tmp_path / "bad_severity.json"
        bad_severity.write_text(json.dumps({"checks": ["ENTRA-ADMIN-001", "High"]}))
        with pytest.raises(RawOutputValidationError, match="must be a mapping"):
            load_risk_severity(bad_severity)


class TestLoadRegistry:
    def test_returns_dict_keyed_by_check_id(self) -> None:
        result = load_registry(FIXTURE_DIR / "registry_sample.json")
        assert "ENTRA-CLOUDADMIN-001" in result

    def test_contains_frameworks(self) -> None:
        result = load_registry(FIXTURE_DIR / "registry_sample.json")
        entry = result["ENTRA-CLOUDADMIN-001"]
        assert "frameworks" in entry
        assert "cis-m365-v6" in entry["frameworks"]

    def test_raises_on_non_list_checks(self, tmp_path: Path) -> None:
        """registry.json with 'checks' as a non-list must raise RawOutputValidationError."""
        import json

        from gxassessms.core.contracts.errors import RawOutputValidationError

        bad_registry = tmp_path / "bad_registry.json"
        bad_registry.write_text(json.dumps({"schemaVersion": "1.0.0", "checks": "not-a-list"}))
        with pytest.raises(RawOutputValidationError, match="must be a list"):
            load_registry(bad_registry)

    def test_raises_on_missing_check_id(self, tmp_path: Path) -> None:
        """Registry entry missing checkId must raise RawOutputValidationError, not KeyError."""
        import json

        from gxassessms.core.contracts.errors import RawOutputValidationError

        bad_registry = tmp_path / "bad_registry.json"
        bad_registry.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0.0",
                    "checks": [
                        {"name": "Missing checkId field", "frameworks": {}},  # no checkId
                    ],
                }
            )
        )
        with pytest.raises(RawOutputValidationError, match="missing 'checkId'"):
            load_registry(bad_registry)

    def test_raises_on_non_string_check_id(self, tmp_path: Path) -> None:
        """Registry entry with a non-string checkId (e.g. int) must raise, not silently create an
        unreachable dict key (CSV lookups always use strings, so int keys are never found)."""
        import json

        from gxassessms.core.contracts.errors import RawOutputValidationError

        bad_registry = tmp_path / "bad_registry.json"
        bad_registry.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0.0",
                    "checks": [
                        {"checkId": 42, "name": "Integer checkId", "frameworks": {}},
                    ],
                }
            )
        )
        with pytest.raises(RawOutputValidationError, match="must be a string"):
            load_registry(bad_registry)


class TestParseSecurityConfigCsv:
    def test_returns_tool_observations(self, severity_map, registry) -> None:
        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        observations = parse_security_config_csv(csv_path, severity_map, registry)
        assert isinstance(observations, list)
        assert all(isinstance(o, ToolObservation) for o in observations)

    def test_observation_count(self, severity_map, registry) -> None:
        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        observations = parse_security_config_csv(csv_path, severity_map, registry)
        assert len(observations) == 9

    def test_native_check_id_is_csv_checkid(self, severity_map, registry) -> None:
        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        observations = parse_security_config_csv(csv_path, severity_map, registry)
        assert observations[0].native_check_id == "ENTRA-SECDEFAULT-001.1"

    def test_status_mapped_correctly(self, severity_map, registry) -> None:
        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        observations = parse_security_config_csv(csv_path, severity_map, registry)
        # First row: Status "Fail"
        assert observations[0].native_status == FindingStatus.FAIL
        # Second row: Status "Pass"
        assert observations[1].native_status == FindingStatus.PASS
        # Fourth row: Status "Warning"
        assert observations[3].native_status == FindingStatus.WARNING
        # Fifth row: Status "Info"
        assert observations[4].native_status == FindingStatus.NOT_APPLICABLE
        # Sixth row: Status "Review"
        assert observations[5].native_status == FindingStatus.MANUAL

    def test_severity_from_risk_severity_json(self, severity_map, registry) -> None:
        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        observations = parse_security_config_csv(csv_path, severity_map, registry)
        # native_severity stores the raw string from risk-severity.json so the
        # normalization layer can resolve it via the tuple-keyed adapter severity_map.
        # ENTRA-SECDEFAULT-001 -> "High"
        assert observations[0].native_severity == "High"
        # ENTRA-AUTHMETHOD-001 -> "Critical"
        assert observations[7].native_severity == "Critical"

    def test_observation_id_format(self, severity_map, registry) -> None:
        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        observations = parse_security_config_csv(csv_path, severity_map, registry)
        assert observations[0].observation_id == "m365assess:ENTRA-SECDEFAULT-001.1"

    def test_title_from_setting_column(self, severity_map, registry) -> None:
        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        observations = parse_security_config_csv(csv_path, severity_map, registry)
        assert observations[0].title == "Security Defaults Enabled"

    def test_tool_source_is_m365_assess(self, severity_map, registry) -> None:
        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        observations = parse_security_config_csv(csv_path, severity_map, registry)
        for obs in observations:
            assert obs.tool == ToolSource.M365_ASSESS

    def test_benchmark_refs_from_registry(self, severity_map, registry) -> None:
        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        observations = parse_security_config_csv(csv_path, severity_map, registry)
        # ENTRA-CLOUDADMIN-001 maps to CIS 1.1.1
        cloud_admin = [o for o in observations if "ENTRA-CLOUDADMIN-001" in o.native_check_id]
        assert len(cloud_admin) == 1
        assert "cis:m365:1.1.1" in cloud_admin[0].benchmark_refs

    def test_category_hint_reflects_collector(self, severity_map, registry) -> None:
        """category_hint in raw_data must match the actual collector, not always COMPLIANCE."""
        from gxassessms.core.domain.enums import Category

        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        observations = parse_security_config_csv(csv_path, severity_map, registry)
        # All rows come from the ENTRA collector -> should be IDENTITY_ACCESS
        for obs in observations:
            assert obs.raw_data["category_hint"] == Category.IDENTITY_ACCESS, (
                f"Expected IDENTITY_ACCESS for ENTRA collector, got {obs.raw_data['category_hint']}"
            )

    def test_benchmark_refs_include_nist_multi_control(self, severity_map, registry) -> None:
        """NIST semicolon-separated controls must each become a separate ref."""
        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        observations = parse_security_config_csv(csv_path, severity_map, registry)
        cloud_admin = [o for o in observations if "ENTRA-CLOUDADMIN-001" in o.native_check_id]
        assert len(cloud_admin) == 1
        refs = cloud_admin[0].benchmark_refs
        assert "nist:800-53:AC-6(5)" in refs
        assert "nist:800-53:AC-2" in refs
        # Ensure they are split, not joined
        assert not any(";" in r for r in refs)

    def test_benchmark_refs_include_soc2(self, severity_map, registry) -> None:
        """SOC2 framework entries must appear in benchmark_refs."""
        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        observations = parse_security_config_csv(csv_path, severity_map, registry)
        cloud_admin = [o for o in observations if "ENTRA-CLOUDADMIN-001" in o.native_check_id]
        assert len(cloud_admin) == 1
        assert "soc2:CC6.3" in cloud_admin[0].benchmark_refs

    def test_severity_warning_logged_for_unknown_check_id(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A check_id absent from a non-empty severity_lookup must emit a WARNING log."""
        import logging

        # Provide a non-empty lookup that doesn't contain any entra check IDs
        sparse_lookup = {"COMPLETELY-DIFFERENT-001": "High"}
        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        with caplog.at_level(logging.WARNING, logger="gxassessms.adapters.m365_assess.parser"):
            observations = parse_security_config_csv(csv_path, sparse_lookup, registry_lookup={})
        assert len(observations) > 0
        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("No severity entry" in msg for msg in warning_messages), (
            f"Expected a severity WARNING log, got: {warning_messages}"
        )
        # All observations should still default to Medium
        for obs in observations:
            assert obs.native_severity == "Medium"

    def test_severity_defaults_to_medium_when_lookup_empty(self) -> None:
        """Empty severity_lookup must produce native_severity='Medium' for all rows."""
        csv_path = FIXTURE_DIR / "entra_security_config.csv"
        observations = parse_security_config_csv(csv_path, severity_lookup={}, registry_lookup={})
        assert len(observations) > 0
        for obs in observations:
            assert obs.native_severity == "Medium", (
                f"Expected 'Medium' default severity, got {obs.native_severity!r}"
            )

    def test_truncated_row_missing_remediation_does_not_crash(self, tmp_path: Path) -> None:
        """CSV row missing the trailing Remediation column must not raise AttributeError.

        csv.DictReader restval=None causes row.get("Remediation", "") to return None
        (key is present, default is ignored), and None.strip() crashes.
        The parser uses restval="" to guarantee string values for all trailing fields.
        """
        truncated_csv = tmp_path / "Trunc-Security-Config.csv"
        truncated_csv.write_text(
            "Category,Setting,CurrentValue,RecommendedValue,Status,CheckId,Remediation\n"
            "Config,Some Setting,On,Off,Fail,ENTRA-TEST-001.1\n"  # Remediation column absent
        )
        observations = parse_security_config_csv(
            truncated_csv, severity_lookup={}, registry_lookup={}
        )
        assert len(observations) == 1
        assert observations[0].raw_data["remediation"] == ""

    def test_category_hint_defaults_to_compliance_when_collector_unknown(
        self, tmp_path: Path
    ) -> None:
        """Unknown collector prefix must produce category_hint=COMPLIANCE."""
        from gxassessms.core.domain.enums import Category

        unknown_csv = tmp_path / "Unknown-Security-Config.csv"
        unknown_csv.write_text(
            "Category,Setting,CurrentValue,RecommendedValue,Status,CheckId,Remediation\n"
            "Test,Test Setting,Current,Recommended,Fail,ZZUNKNOWN-TEST-001.1,Fix it\n"
        )
        observations = parse_security_config_csv(
            unknown_csv, severity_lookup={}, registry_lookup={}
        )
        assert len(observations) == 1
        assert observations[0].raw_data["category_hint"] == Category.COMPLIANCE
