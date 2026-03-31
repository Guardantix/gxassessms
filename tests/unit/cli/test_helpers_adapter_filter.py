"""Tests for filter_and_validate_adapters helper."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from gxassessms.cli._helpers import filter_and_validate_adapters


class TestFilterAndValidateAdapters:
    def test_no_tools_configured_returns_all_adapters(self) -> None:
        """When config.tools is empty/None, return all adapters unchanged."""
        config = MagicMock()
        config.tools = None
        adapter_a = MagicMock()
        adapter_a.tool_name = "scubagear"
        adapter_b = MagicMock()
        adapter_b.tool_name = "maester"
        result = filter_and_validate_adapters(config, [adapter_a, adapter_b])
        assert len(result) == 2

    def test_filters_to_enabled_tools_only(self) -> None:
        """Only adapters matching enabled tools survive filtering."""
        config = MagicMock()
        tc_enabled = MagicMock()
        tc_enabled.enabled = True
        tc_disabled = MagicMock()
        tc_disabled.enabled = False
        config.tools = {"scubagear": tc_enabled, "maester": tc_disabled}
        adapter_a = MagicMock()
        adapter_a.tool_name = "scubagear"
        adapter_b = MagicMock()
        adapter_b.tool_name = "maester"
        result = filter_and_validate_adapters(config, [adapter_a, adapter_b])
        assert len(result) == 1
        assert result[0].tool_name == "scubagear"

    def test_raises_system_exit_on_missing_adapter(self) -> None:
        """Enabled tool with no matching adapter -> SystemExit(1)."""
        config = MagicMock()
        tc_scuba = MagicMock()
        tc_scuba.enabled = True
        tc_maester = MagicMock()
        tc_maester.enabled = True
        config.tools = {"scubagear": tc_scuba, "maester": tc_maester}
        adapter_a = MagicMock()
        adapter_a.tool_name = "scubagear"
        with pytest.raises(SystemExit):
            filter_and_validate_adapters(config, [adapter_a])

    def test_case_insensitive_matching(self) -> None:
        """Tool names should match case-insensitively."""
        config = MagicMock()
        tc = MagicMock()
        tc.enabled = True
        config.tools = {"ScubaGear": tc}
        adapter = MagicMock()
        adapter.tool_name = "scubagear"
        result = filter_and_validate_adapters(config, [adapter])
        assert len(result) == 1

    def test_all_enabled_present_returns_filtered_list(self) -> None:
        """When all enabled tools have adapters, return filtered list (no error)."""
        config = MagicMock()
        tc = MagicMock()
        tc.enabled = True
        config.tools = {"scubagear": tc}
        adapter = MagicMock()
        adapter.tool_name = "scubagear"
        extra = MagicMock()
        extra.tool_name = "monkey365"
        result = filter_and_validate_adapters(config, [adapter, extra])
        assert len(result) == 1
        assert result[0].tool_name == "scubagear"

    def test_empty_dict_tools_returns_all_adapters(self) -> None:
        """When config.tools is an empty dict, return all adapters unchanged."""
        config = MagicMock()
        config.tools = {}
        adapter = MagicMock()
        adapter.tool_name = "scubagear"
        result = filter_and_validate_adapters(config, [adapter])
        assert len(result) == 1
