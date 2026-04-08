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

import pytest

from gxassessms.adapters import AdapterRegistry
from gxassessms.core.config.config import AuthConfig, EngagementConfig
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


def _make_config(
    *,
    qa_model: str = "claude-opus-4-6",
    qa_token_budget: int = 50000,
    client_name: str = "Acme Corp",
) -> EngagementConfig:
    """Build a minimal EngagementConfig for tests."""
    return EngagementConfig(
        client_name=client_name,
        tenant_id="00000000-0000-0000-0000-000000000001",
        auth=AuthConfig(
            method="client_credential",
            tenant_id="00000000-0000-0000-0000-000000000001",
            client_id="00000000-0000-0000-0000-000000000002",
            client_secret_env="GX_SECRET",  # pragma: allowlist secret
        ),
        tools={},
        qa_model=qa_model,
        qa_token_budget=qa_token_budget,
    )


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

    def test_selects_highest_priority_plugin(self):
        """When multiple plugins registered, highest priority wins."""
        from gxassessms.cli._helpers import discover_plugin

        low_inst = MagicMock(name="low_inst")
        high_inst = MagicMock(name="high_inst")
        LowCls = MagicMock(return_value=low_inst)
        LowCls.priority = 0
        HighCls = MagicMock(return_value=high_inst)
        HighCls.priority = 100
        disc_result = _make_result(plugins={"low": LowCls, "high": HighCls})
        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            result = discover_plugin("some.group")
        assert result is high_inst

    def test_name_override_selects_specific_plugin(self):
        """Explicit name parameter picks that specific plugin."""
        from gxassessms.cli._helpers import discover_plugin

        low_inst = MagicMock(name="low_inst")
        high_inst = MagicMock(name="high_inst")
        LowCls = MagicMock(return_value=low_inst)
        LowCls.priority = 0
        HighCls = MagicMock(return_value=high_inst)
        HighCls.priority = 100
        disc_result = _make_result(plugins={"low": LowCls, "high": HighCls})
        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            result = discover_plugin("some.group", name="low")
        assert result is low_inst

    def test_name_override_returns_none_for_missing(self, caplog):
        """Explicit name that doesn't exist returns None and logs warning."""
        from gxassessms.cli._helpers import discover_plugin

        ExistingCls = MagicMock(return_value=MagicMock())
        disc_result = _make_result(plugins={"existing": ExistingCls})
        with (
            patch("gxassessms.registry.discover_entry_points", return_value=disc_result),
            caplog.at_level(logging.WARNING),
        ):
            result = discover_plugin("some.group", name="nonexistent")
        assert result is None
        assert any("nonexistent" in r.message for r in caplog.records)

    def test_priority_defaults_to_zero_when_missing(self):
        """Plugins without priority attribute are treated as priority 0."""
        from gxassessms.cli._helpers import discover_plugin

        no_pri_inst = MagicMock(name="no_pri_inst")
        high_inst = MagicMock(name="high_inst")
        NoPriCls = MagicMock(return_value=no_pri_inst)
        del NoPriCls.priority  # ensure attribute doesn't exist
        HighCls = MagicMock(return_value=high_inst)
        HighCls.priority = 50
        disc_result = _make_result(plugins={"no_pri": NoPriCls, "high": HighCls})
        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            result = discover_plugin("some.group")
        assert result is high_inst

    def test_equal_priority_preserves_discovery_order(self):
        """Equal-priority plugins: first discovered wins (stable sort)."""
        from gxassessms.cli._helpers import discover_plugin

        first_inst = MagicMock(name="first_inst")
        second_inst = MagicMock(name="second_inst")
        FirstCls = MagicMock(return_value=first_inst)
        FirstCls.priority = 0
        SecondCls = MagicMock(return_value=second_inst)
        SecondCls.priority = 0
        disc_result = _make_result(plugins={"first": FirstCls, "second": SecondCls})
        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            result = discover_plugin("some.group")
        assert result is first_inst

    def test_single_plugin_always_selected(self):
        """Single plugin is returned regardless of priority value."""
        from gxassessms.cli._helpers import discover_plugin

        inst = MagicMock(name="inst")
        Cls = MagicMock(return_value=inst)
        Cls.priority = 42
        disc_result = _make_result(plugins={"only": Cls})
        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            result = discover_plugin("some.group")
        assert result is inst

    def test_config_kwargs_passed_to_qa_strategy_loop_path(self):
        """Loop path: config provided for qa_strategies group -> cls called with kwargs."""
        mock_instance = MagicMock(name="qa_inst")
        MockCls = MagicMock(return_value=mock_instance)
        disc_result = _make_result(plugins={"gx_qa": MockCls})
        config = _make_config()

        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            from gxassessms.cli._helpers import discover_plugin

            result = discover_plugin("gxassessms.qa_strategies", config=config)

        assert result is mock_instance
        MockCls.assert_called_once_with(
            model=config.qa_model,
            token_budget=config.qa_token_budget,
            client_name=config.client_name,
        )

    def test_config_kwargs_passed_to_qa_strategy_named_path(self):
        """Named path: config provided for qa_strategies group -> cls called with kwargs."""
        mock_instance = MagicMock(name="qa_inst")
        MockCls = MagicMock(return_value=mock_instance)
        disc_result = _make_result(plugins={"gx_qa": MockCls})
        config = _make_config()

        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            from gxassessms.cli._helpers import discover_plugin

            result = discover_plugin("gxassessms.qa_strategies", name="gx_qa", config=config)

        assert result is mock_instance
        MockCls.assert_called_once_with(
            model=config.qa_model,
            token_budget=config.qa_token_budget,
            client_name=config.client_name,
        )

    def test_config_kwargs_fallback_to_zero_arg_on_typeerror_loop(self):
        """Loop path: TypeError from kwargs call -> retried with no-arg, success."""
        mock_instance = MagicMock(name="fallback_inst")

        def side_effect(*args, **kwargs):
            if kwargs:
                raise TypeError("unexpected keyword argument 'model'")
            return mock_instance

        MockCls = MagicMock(side_effect=side_effect)
        disc_result = _make_result(plugins={"legacy_qa": MockCls})
        config = _make_config()

        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            from gxassessms.cli._helpers import discover_plugin

            result = discover_plugin("gxassessms.qa_strategies", config=config)

        assert result is mock_instance
        assert MockCls.call_count == 2  # kwargs attempt + no-arg fallback

    def test_config_kwargs_fallback_to_zero_arg_on_typeerror_named(self):
        """Named path: TypeError from kwargs call -> retried with no-arg, success."""
        mock_instance = MagicMock(name="fallback_inst")

        def side_effect(*args, **kwargs):
            if kwargs:
                raise TypeError("unexpected keyword argument 'model'")
            return mock_instance

        MockCls = MagicMock(side_effect=side_effect)
        disc_result = _make_result(plugins={"legacy_qa": MockCls})
        config = _make_config()

        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            from gxassessms.cli._helpers import discover_plugin

            result = discover_plugin("gxassessms.qa_strategies", name="legacy_qa", config=config)

        assert result is mock_instance
        assert MockCls.call_count == 2

    def test_non_typeerror_from_kwargs_is_not_swallowed(self, caplog):
        """ValueError from kwargs call is NOT silently swallowed -- plugin is skipped."""
        MockCls = MagicMock(side_effect=ValueError("bad model name"))
        disc_result = _make_result(plugins={"bad_qa": MockCls})
        config = _make_config()

        with (
            patch("gxassessms.registry.discover_entry_points", return_value=disc_result),
            caplog.at_level(logging.WARNING, logger="gxassessms.cli._helpers"),
        ):
            from gxassessms.cli._helpers import discover_plugin

            result = discover_plugin("gxassessms.qa_strategies", config=config)

        assert result is None
        assert any("bad_qa" in r.message for r in caplog.records)
        MockCls.assert_called_once()  # called with kwargs, not retried

    def test_config_not_applied_for_non_qa_group(self):
        """Config provided but group is not qa_strategies -> cls() called with no kwargs."""
        mock_instance = MagicMock(name="adapter_inst")
        MockCls = MagicMock(return_value=mock_instance)
        disc_result = _make_result(plugins={"my_adapter": MockCls})
        config = _make_config()

        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            from gxassessms.cli._helpers import discover_plugin

            result = discover_plugin("gxassessms.adapters", config=config)

        assert result is mock_instance
        MockCls.assert_called_once_with()  # no kwargs

    def test_none_config_uses_zero_arg_for_qa_group(self):
        """config=None for qa_strategies -> cls() called with no kwargs."""
        mock_instance = MagicMock(name="qa_inst")
        MockCls = MagicMock(return_value=mock_instance)
        disc_result = _make_result(plugins={"noop": MockCls})

        with patch("gxassessms.registry.discover_entry_points", return_value=disc_result):
            from gxassessms.cli._helpers import discover_plugin

            result = discover_plugin("gxassessms.qa_strategies", config=None)

        assert result is mock_instance
        MockCls.assert_called_once_with()


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


# ---------------------------------------------------------------------------
# _load_policy_rules
# ---------------------------------------------------------------------------


class TestLoadPolicyRules:
    def test_loads_real_normalization_yaml(self):
        """Verifies importlib.resources path resolves the bundled YAML."""
        from gxassessms.cli._helpers import _load_policy_rules

        rules = _load_policy_rules("normalization.yaml")
        assert isinstance(rules, dict)
        assert "fallback_severity" in rules or "default_severity_map" in rules

    def test_raises_config_error_on_missing_file(self):
        from gxassessms.cli._helpers import _load_policy_rules
        from gxassessms.core.contracts.errors import ConfigError

        with pytest.raises(ConfigError, match="not found"):
            _load_policy_rules("no_such_file.yaml")


# ---------------------------------------------------------------------------
# build_normalization_policy
# ---------------------------------------------------------------------------


class TestBuildNormalizationPolicy:
    def test_returns_default_when_no_override_registered(self):
        from gxassessms.cli._helpers import build_normalization_policy
        from gxassessms.policy.normalization import DefaultNormalizationPolicy

        with patch("gxassessms.registry.discover_entry_points") as md:
            md.return_value = _make_result({})
            with patch("gxassessms.cli._helpers._load_policy_rules", return_value={}):
                policy = build_normalization_policy()
        assert isinstance(policy, DefaultNormalizationPolicy)

    def test_uses_override_when_registered(self):
        from gxassessms.cli._helpers import build_normalization_policy

        mock_cls = MagicMock(return_value=MagicMock())
        with patch("gxassessms.registry.discover_entry_points") as md:
            md.return_value = _make_result({"normalization": mock_cls})
            with patch("gxassessms.cli._helpers._load_policy_rules", return_value={}):
                build_normalization_policy()
        mock_cls.assert_called_once_with(rules={})

    def test_falls_back_on_override_type_error(self):
        from gxassessms.cli._helpers import build_normalization_policy
        from gxassessms.policy.normalization import DefaultNormalizationPolicy

        with patch("gxassessms.registry.discover_entry_points") as md:
            md.return_value = _make_result(
                {"normalization": MagicMock(side_effect=TypeError("bad"))}
            )
            with patch("gxassessms.cli._helpers._load_policy_rules", return_value={}):
                policy = build_normalization_policy()
        assert isinstance(policy, DefaultNormalizationPolicy)

    def test_builtin_class_registered_as_override_still_works(self):
        from gxassessms.cli._helpers import build_normalization_policy
        from gxassessms.policy.normalization import DefaultNormalizationPolicy

        with patch("gxassessms.registry.discover_entry_points") as md:
            md.return_value = _make_result({"normalization": DefaultNormalizationPolicy})
            with patch("gxassessms.cli._helpers._load_policy_rules", return_value={}):
                policy = build_normalization_policy()
        assert isinstance(policy, DefaultNormalizationPolicy)


# ---------------------------------------------------------------------------
# build_consolidation_rule
# ---------------------------------------------------------------------------


class TestBuildConsolidationRule:
    def test_returns_default_when_no_override_registered(self):
        from gxassessms.cli._helpers import build_consolidation_rule
        from gxassessms.consolidation.rules import DefaultConsolidationRule

        with patch("gxassessms.registry.discover_entry_points") as md:
            md.return_value = _make_result({})
            with patch("gxassessms.cli._helpers._load_policy_rules", return_value={}):
                rule = build_consolidation_rule()
        assert isinstance(rule, DefaultConsolidationRule)

    def test_uses_override_when_registered(self):
        from gxassessms.cli._helpers import build_consolidation_rule

        mock_cls = MagicMock(return_value=MagicMock())
        with patch("gxassessms.registry.discover_entry_points") as md:
            md.return_value = _make_result({"default": mock_cls})
            with patch("gxassessms.cli._helpers._load_policy_rules", return_value={}):
                build_consolidation_rule()
        mock_cls.assert_called_once()
