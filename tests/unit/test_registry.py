"""Tests for generic entry-point discovery utilities (registry.py).

Tests are written first (TDD). registry.py is implemented to pass them.

Entry-point discovery is mocked via patch('gxassessms.registry.entry_points')
so no real package installation is required.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# TestDiscoveryError
# ---------------------------------------------------------------------------


class TestDiscoveryError:
    """DiscoveryError is a frozen dataclass with three string fields."""

    def test_fields_accessible(self) -> None:
        from gxassessms.registry import DiscoveryError

        err = DiscoveryError(
            plugin_name="my_plugin",
            error_type="ImportError",
            message="No module named 'missing_dep'",
        )
        assert err.plugin_name == "my_plugin"
        assert err.error_type == "ImportError"
        assert err.message == "No module named 'missing_dep'"

    def test_frozen(self) -> None:
        from gxassessms.registry import DiscoveryError

        err = DiscoveryError(
            plugin_name="p",
            error_type="E",
            message="m",
        )
        with pytest.raises((AttributeError, TypeError)):
            err.plugin_name = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TestDiscoveryResult
# ---------------------------------------------------------------------------


class TestDiscoveryResult:
    """DiscoveryResult holds loaded plugins and any per-plugin errors."""

    def _make_result(
        self,
        plugins: dict | None = None,
        errors: list | None = None,
    ):
        from gxassessms.registry import DiscoveryResult

        return DiscoveryResult(
            plugins=plugins or {},
            errors=errors or [],
        )

    def test_names_empty(self) -> None:
        result = self._make_result()
        assert result.names == []

    def test_names_returns_plugin_keys(self) -> None:
        result = self._make_result(plugins={"alpha": object(), "beta": object()})
        assert sorted(result.names) == ["alpha", "beta"]

    def test_get_existing(self) -> None:
        sentinel = object()
        result = self._make_result(plugins={"thing": sentinel})
        assert result.get("thing") is sentinel

    def test_get_missing_returns_none(self) -> None:
        result = self._make_result(plugins={"thing": object()})
        assert result.get("nope") is None

    def test_has_errors_false_when_no_errors(self) -> None:
        result = self._make_result()
        assert result.has_errors is False

    def test_has_errors_true_when_errors_present(self) -> None:
        from gxassessms.registry import DiscoveryError

        err = DiscoveryError(plugin_name="x", error_type="ImportError", message="boom")
        result = self._make_result(errors=[err])
        assert result.has_errors is True


# ---------------------------------------------------------------------------
# TestDiscoverEntryPoints
# ---------------------------------------------------------------------------


class TestDiscoverEntryPoints:
    """discover_entry_points() loads all entry points in a given group."""

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_ep(name: str, load_return=None, load_raises=None) -> MagicMock:
        """Build a mock entry_point whose .name and .load() behave as specified."""
        ep = MagicMock()
        ep.name = name
        if load_raises is not None:
            ep.load.side_effect = load_raises
        else:
            ep.load.return_value = load_return
        return ep

    # ------------------------------------------------------------------
    # tests
    # ------------------------------------------------------------------

    def test_empty_group_returns_empty_result(self) -> None:
        from gxassessms.registry import discover_entry_points

        with patch("gxassessms.registry.entry_points") as mock_ep:
            mock_ep.return_value = []
            result = discover_entry_points("gxassessms.adapters")

        assert result.plugins == {}
        assert result.errors == []
        assert result.names == []
        assert result.has_errors is False

    def test_successful_discovery(self) -> None:
        from gxassessms.registry import discover_entry_points

        plugin_obj = object()
        ep = self._make_ep("scubagear", load_return=plugin_obj)

        with patch("gxassessms.registry.entry_points") as mock_ep:
            mock_ep.return_value = [ep]
            result = discover_entry_points("gxassessms.adapters")

        assert "scubagear" in result.plugins
        assert result.plugins["scubagear"] is plugin_obj
        assert result.errors == []

    def test_import_error_recorded_as_discovery_error(self) -> None:
        from gxassessms.registry import DiscoveryError, discover_entry_points

        ep = self._make_ep(
            "broken_adapter",
            load_raises=ImportError("No module named 'missing_dep'"),
        )

        with patch("gxassessms.registry.entry_points") as mock_ep:
            mock_ep.return_value = [ep]
            result = discover_entry_points("gxassessms.adapters")

        assert result.plugins == {}
        assert len(result.errors) == 1
        err: DiscoveryError = result.errors[0]
        assert err.plugin_name == "broken_adapter"
        assert err.error_type == "ImportError"
        assert "missing_dep" in err.message

    def test_attribute_error_recorded_as_discovery_error(self) -> None:
        from gxassessms.registry import DiscoveryError, discover_entry_points

        ep = self._make_ep(
            "bad_attr",
            load_raises=AttributeError("module has no attribute 'Plugin'"),
        )

        with patch("gxassessms.registry.entry_points") as mock_ep:
            mock_ep.return_value = [ep]
            result = discover_entry_points("gxassessms.adapters")

        assert result.plugins == {}
        assert len(result.errors) == 1
        err: DiscoveryError = result.errors[0]
        assert err.plugin_name == "bad_attr"
        assert err.error_type == "AttributeError"

    def test_mixed_success_and_failure(self) -> None:
        from gxassessms.registry import discover_entry_points

        good_obj = object()
        ep_good = self._make_ep("good_plugin", load_return=good_obj)
        ep_bad = self._make_ep(
            "bad_plugin",
            load_raises=ImportError("missing"),
        )

        with patch("gxassessms.registry.entry_points") as mock_ep:
            mock_ep.return_value = [ep_good, ep_bad]
            result = discover_entry_points("gxassessms.adapters")

        assert "good_plugin" in result.plugins
        assert result.plugins["good_plugin"] is good_obj
        assert "bad_plugin" not in result.plugins
        assert len(result.errors) == 1
        assert result.errors[0].plugin_name == "bad_plugin"

    def test_entry_points_called_with_correct_group(self) -> None:
        from gxassessms.registry import discover_entry_points

        with patch("gxassessms.registry.entry_points") as mock_ep:
            mock_ep.return_value = []
            discover_entry_points("gxassessms.renderers")

        mock_ep.assert_called_once_with(group="gxassessms.renderers")

    def test_multiple_successful_plugins(self) -> None:
        from gxassessms.registry import discover_entry_points

        objs = [object(), object(), object()]
        eps = [
            self._make_ep("alpha", load_return=objs[0]),
            self._make_ep("beta", load_return=objs[1]),
            self._make_ep("gamma", load_return=objs[2]),
        ]

        with patch("gxassessms.registry.entry_points") as mock_ep:
            mock_ep.return_value = eps
            result = discover_entry_points("gxassessms.policies")

        assert sorted(result.names) == ["alpha", "beta", "gamma"]
        assert result.has_errors is False
        for name, obj in zip(["alpha", "beta", "gamma"], objs, strict=True):
            assert result.get(name) is obj
