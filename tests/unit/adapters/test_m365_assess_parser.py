"""Tests for M365-Assess CSV parser."""

from pathlib import Path

import pytest

from gxassessms.adapters.m365_assess.parser import (
    load_registry,
    load_risk_severity,
    parse_security_config_csv,
)
from gxassessms.core.domain.enums import FindingStatus, Severity, ToolSource
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


class TestLoadRegistry:
    def test_returns_dict_keyed_by_check_id(self) -> None:
        result = load_registry(FIXTURE_DIR / "registry_sample.json")
        assert "ENTRA-CLOUDADMIN-001" in result

    def test_contains_frameworks(self) -> None:
        result = load_registry(FIXTURE_DIR / "registry_sample.json")
        entry = result["ENTRA-CLOUDADMIN-001"]
        assert "frameworks" in entry
        assert "cis-m365-v6" in entry["frameworks"]


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
        # ENTRA-SECDEFAULT-001 -> High
        assert observations[0].native_severity == Severity.HIGH
        # ENTRA-AUTHMETHOD-001 -> Critical
        assert observations[7].native_severity == Severity.CRITICAL

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
