"""Tests for ToolObservation.native_category field."""

from gxassessms.core.domain.models import ToolObservation


def _make_obs(**kwargs: object) -> ToolObservation:
    defaults = {
        "observation_id": "obs-1",
        "tool": "ScubaGear",
        "native_check_id": "CIS-1.1",
        "title": "Test check",
        "native_severity": "HIGH",
        "native_status": "FAIL",
        "description": "desc",
    }
    defaults.update(kwargs)
    return ToolObservation(**defaults)  # type: ignore[arg-type]


class TestNativeCategory:
    def test_defaults_to_none(self) -> None:
        obs = _make_obs()
        assert obs.native_category is None

    def test_round_trips_string_value(self) -> None:
        obs = _make_obs(native_category="Identity")
        assert obs.native_category == "Identity"
