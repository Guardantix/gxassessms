"""Tests for ToolObservation.native_category field."""

from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import ToolObservation


class TestToolObservationNativeCategory:
    def test_native_category_defaults_to_none(self) -> None:
        obs = ToolObservation(
            observation_id="test:1",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="Test",
            native_severity="Shall",
            native_status="Fail",
            description="Test observation.",
        )
        assert obs.native_category is None

    def test_native_category_set_explicitly(self) -> None:
        obs = ToolObservation(
            observation_id="test:2",
            tool=ToolSource.SECURE_SCORE,
            native_check_id="MFARegistrationV2",
            title="MFA Registration",
            native_severity="CRITICAL",
            native_status="PASS",
            description="Test.",
            native_category="Identity",
        )
        assert obs.native_category == "Identity"

    def test_native_category_survives_round_trip(self) -> None:
        obs = ToolObservation(
            observation_id="test:3",
            tool=ToolSource.SECURE_SCORE,
            native_check_id="DLPEnabled",
            title="DLP",
            native_severity="HIGH",
            native_status="FAIL",
            description="Test.",
            native_category="Data",
        )
        json_str = obs.model_dump_json()
        restored = ToolObservation.model_validate_json(json_str)
        assert restored.native_category == "Data"

    def test_native_category_none_survives_round_trip(self) -> None:
        obs = ToolObservation(
            observation_id="test:4",
            tool=ToolSource.SCUBAGEAR,
            native_check_id="MS.AAD.1.1v1",
            title="Test",
            native_severity="Shall",
            native_status="Fail",
            description="Test.",
        )
        json_str = obs.model_dump_json()
        restored = ToolObservation.model_validate_json(json_str)
        assert restored.native_category is None
