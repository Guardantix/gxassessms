"""Unit tests for CLI helper factories in gxassessms.cli._helpers.

Covers discover_cli_adapters(), discover_plugin(), and discover_all_plugins().

Patch targets are based on import paths in _helpers.py:
- discover_cli_adapters uses: from gxassessms.adapters import discover_adapters
  -> patch at gxassessms.adapters.discover_adapters
- discover_plugin / discover_all_plugins use: from gxassessms.registry import discover_entry_points
  -> patch at gxassessms.registry.discover_entry_points

Return value shapes:
- discover_adapters() -> AdapterRegistry(adapters={name: cls}, validation_errors=[DiscoveryError])
- discover_entry_points(group) -> DiscoveryResult(plugins={name: cls}, errors=[DiscoveryError])
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

from gxassessms.adapters import AdapterRegistry
from gxassessms.registry import DiscoveryError, DiscoveryResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_registry(adapters: dict, validation_errors: list | None = None) -> AdapterRegistry:
    """Build an AdapterRegistry with the given adapters dict and errors list."""
    return AdapterRegistry(
        adapters=adapters,
        validation_errors=validation_errors or [],
    )


def _make_result(plugins: dict, errors: list | None = None) -> DiscoveryResult:
    """Build a DiscoveryResult with the given plugins dict and errors list."""
    return DiscoveryResult(
        plugins=plugins,
        errors=errors or [],
    )


def _make_error(name: str = "bad_plugin", msg: str = "some error") -> DiscoveryError:
    return DiscoveryError(plugin_name=name, error_type="ValidationError", message=msg)


# ---------------------------------------------------------------------------
# discover_cli_adapters
# ---------------------------------------------------------------------------


class TestDiscoverCliAdapters:
    """Tests for discover_cli_adapters()."""

    def test_returns_instances_when_discovery_succeeds(self):
        """Happy path: valid adapter class -> instantiated object returned."""
        mock_instance = MagicMock(name="adapter_instance")
        MockCls = MagicMock(return_value=mock_instance)
        registry = _make_registry(adapters={"my_adapter": MockCls})

        with patch("gxassessms.adapters.discover_adapters", return_value=registry):
            from gxassessms.cli._helpers import discover_cli_adapters

            result = discover_cli_adapters()

        assert result == [mock_instance]
        MockCls.assert_called_once_with()

    def test_logs_warning_for_validation_errors(self, caplog):
        """Validation errors on the registry are logged as WARNINGs."""
        err = _make_error(name="broken_adapter", msg="missing required attribute")
        registry = _make_registry(adapters={}, validation_errors=[err])

        with (
            patch("gxassessms.adapters.discover_adapters", return_value=registry),
            caplog.at_level(logging.WARNING, logger="gxassessms.cli._helpers"),
        ):
            from gxassessms.cli._helpers import discover_cli_adapters

            result = discover_cli_adapters()

        assert result == []
        assert any("broken_adapter" in r.message for r in caplog.records)

    def test_drops_adapter_that_raises_on_instantiation_logs_warning(self, caplog):
        """An adapter whose __init__ raises is dropped and WARNING is logged."""
        MockCls = MagicMock(side_effect=RuntimeError("init failed"))
        registry = _make_registry(adapters={"bad_adapter": MockCls})

        with (
            patch("gxassessms.adapters.discover_adapters", return_value=registry),
            caplog.at_level(logging.WARNING, logger="gxassessms.cli._helpers"),
        ):
            from gxassessms.cli._helpers import discover_cli_adapters

            result = discover_cli_adapters()

        assert result == []
        assert any("bad_adapter" in r.message for r in caplog.records)

    def test_returns_empty_list_when_all_adapters_fail(self):
        """No crash when every adapter fails instantiation; empty list returned."""
        MockCls1 = MagicMock(side_effect=TypeError("bad type"))
        MockCls2 = MagicMock(side_effect=ValueError("bad value"))
        registry = _make_registry(adapters={"a1": MockCls1, "a2": MockCls2})

        with patch("gxassessms.adapters.discover_adapters", return_value=registry):
            from gxassessms.cli._helpers import discover_cli_adapters

            result = discover_cli_adapters()

        assert result == []

    def test_returns_only_successful_adapters_on_partial_failure(self):
        """Successful adapters are returned even when some fail."""
        good_instance = MagicMock(name="good_instance")
        GoodCls = MagicMock(return_value=good_instance)
        BadCls = MagicMock(side_effect=RuntimeError("broken"))
        registry = _make_registry(adapters={"good": GoodCls, "bad": BadCls})

        with patch("gxassessms.adapters.discover_adapters", return_value=registry):
            from gxassessms.cli._helpers import discover_cli_adapters

            result = discover_cli_adapters()

        assert result == [good_instance]


# ---------------------------------------------------------------------------
# discover_plugin
# ---------------------------------------------------------------------------


class TestDiscoverPlugin:
    """Tests for discover_plugin(group)."""

    def test_returns_none_when_no_plugins_registered(self):
        """Empty DiscoveryResult -> None returned, no crash."""
        disc_result = _make_result(plugins={})

        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            from gxassessms.cli._helpers import discover_plugin

            result = discover_plugin("some.group")

        assert result is None

    def test_returns_instance_when_plugin_registered(self):
        """Single registered plugin class -> instantiated object returned."""
        mock_instance = MagicMock(name="plugin_instance")
        MockCls = MagicMock(return_value=mock_instance)
        disc_result = _make_result(plugins={"my_plugin": MockCls})

        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            from gxassessms.cli._helpers import discover_plugin

            result = discover_plugin("some.group")

        assert result is mock_instance
        MockCls.assert_called_once_with()

    def test_returns_none_logs_warning_when_plugin_raises(self, caplog):
        """Plugin that raises on __init__ -> None returned, WARNING logged."""
        MockCls = MagicMock(side_effect=RuntimeError("plugin broken"))
        disc_result = _make_result(plugins={"crashing_plugin": MockCls})

        with (
            patch("gxassessms.registry.discover_entry_points", return_value=disc_result),
            caplog.at_level(logging.WARNING, logger="gxassessms.cli._helpers"),
        ):
            from gxassessms.cli._helpers import discover_plugin

            result = discover_plugin("some.group")

        assert result is None
        assert any("crashing_plugin" in r.message for r in caplog.records)

    def test_logs_warning_for_discovery_errors(self, caplog):
        """Errors in DiscoveryResult.errors are logged as WARNINGs."""
        err = _make_error(name="broken_ep", msg="import failed")
        disc_result = _make_result(plugins={}, errors=[err])

        with (
            patch("gxassessms.registry.discover_entry_points", return_value=disc_result),
            caplog.at_level(logging.WARNING, logger="gxassessms.cli._helpers"),
        ):
            from gxassessms.cli._helpers import discover_plugin

            result = discover_plugin("some.group")

        assert result is None
        assert any("broken_ep" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# discover_all_plugins
# ---------------------------------------------------------------------------


class TestDiscoverAllPlugins:
    """Tests for discover_all_plugins(group)."""

    def test_returns_empty_list_when_no_plugins(self):
        """Empty DiscoveryResult -> empty list, no crash."""
        disc_result = _make_result(plugins={})

        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            from gxassessms.cli._helpers import discover_all_plugins

            result = discover_all_plugins("some.group")

        assert result == []

    def test_returns_all_instantiated_plugins(self):
        """All registered plugin classes are instantiated and returned."""
        inst1 = MagicMock(name="inst1")
        inst2 = MagicMock(name="inst2")
        Cls1 = MagicMock(return_value=inst1)
        Cls2 = MagicMock(return_value=inst2)
        disc_result = _make_result(plugins={"p1": Cls1, "p2": Cls2})

        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            from gxassessms.cli._helpers import discover_all_plugins

            result = discover_all_plugins("some.group")

        assert set(result) == {inst1, inst2}
        Cls1.assert_called_once_with()
        Cls2.assert_called_once_with()

    def test_drops_failing_plugins_returns_successful_ones(self, caplog):
        """Failing plugin is dropped with WARNING; successful ones returned."""
        good_inst = MagicMock(name="good_inst")
        GoodCls = MagicMock(return_value=good_inst)
        BadCls = MagicMock(side_effect=ValueError("bad plugin"))
        disc_result = _make_result(plugins={"good": GoodCls, "bad": BadCls})

        with (
            patch("gxassessms.registry.discover_entry_points", return_value=disc_result),
            caplog.at_level(logging.WARNING, logger="gxassessms.cli._helpers"),
        ):
            from gxassessms.cli._helpers import discover_all_plugins

            result = discover_all_plugins("some.group")

        assert result == [good_inst]
        assert any("bad" in r.message for r in caplog.records)

    def test_logs_discovery_errors(self, caplog):
        """Errors in DiscoveryResult.errors are logged as WARNINGs."""
        err = _make_error(name="ep_error", msg="load failed")
        disc_result = _make_result(plugins={}, errors=[err])

        with (
            patch("gxassessms.registry.discover_entry_points", return_value=disc_result),
            caplog.at_level(logging.WARNING, logger="gxassessms.cli._helpers"),
        ):
            from gxassessms.cli._helpers import discover_all_plugins

            result = discover_all_plugins("some.group")

        assert result == []
        assert any("ep_error" in r.message for r in caplog.records)
