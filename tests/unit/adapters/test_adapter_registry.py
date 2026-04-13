"""Tests for adapter registry -- AdapterRegistry, _validate_adapter, discover_adapters.

Covers Protocol validation, instantiation error handling, frozen dataclass
semantics, and _REQUIRED_ATTRIBUTES sync with ToolAdapter Protocol.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Any
from unittest.mock import patch

import pytest

from gxassessms.core.domain.constants import AdapterCapability
from gxassessms.core.domain.enums import ToolSource

# ---------------------------------------------------------------------------
# Mock adapter classes
# ---------------------------------------------------------------------------


class _ValidAdapter:
    """Minimal valid adapter class for testing."""

    tool_name: str = "TestTool"
    storage_slug: str = "testtool"
    tool_source: ToolSource = ToolSource.SCUBAGEAR
    capabilities: frozenset[AdapterCapability] = frozenset({"collect", "parse"})

    def check_prerequisites(self) -> Any:
        return None

    def authenticate(self, config: Any) -> None:
        return None

    def collect(self, config: Any, auth: Any) -> Any:
        return None

    def validate_raw(self, raw: Any) -> None:
        pass

    def parse(self, raw: Any) -> list[Any]:
        return []

    def coverage(self, raw: Any) -> list[Any]:
        return []


class _MissingParseAdapter:
    """Adapter missing the 'parse' method."""

    tool_name: str = "Broken"
    storage_slug: str = "broken"
    tool_source: ToolSource = ToolSource.SCUBAGEAR
    capabilities: frozenset[AdapterCapability] = frozenset()

    def check_prerequisites(self) -> Any:
        return None

    def authenticate(self, config: Any) -> None:
        return None

    def collect(self, config: Any, auth: Any) -> Any:
        return None

    def validate_raw(self, raw: Any) -> None:
        pass

    def coverage(self, raw: Any) -> list[Any]:
        return []


class _EmptyToolNameAdapter(_ValidAdapter):
    tool_name: str = ""


class _NonStringToolNameAdapter(_ValidAdapter):
    tool_name: int = 42  # type: ignore[assignment]


class _TypeErrorOnInit:
    """Adapter whose __init__ requires arguments."""

    tool_name: str = "Broken"
    storage_slug: str = "broken"
    tool_source: ToolSource = ToolSource.SCUBAGEAR
    capabilities: frozenset[AdapterCapability] = frozenset()
    check_prerequisites = authenticate = collect = validate_raw = parse = coverage = None

    def __init__(self, required_arg: str) -> None:
        pass


class _ImportErrorOnInit(_ValidAdapter):
    def __init__(self) -> None:
        raise ImportError("missing dependency")


class _AttributeErrorOnInit(_ValidAdapter):
    def __init__(self) -> None:
        raise AttributeError("bad descriptor")


class _OSErrorOnInit(_ValidAdapter):
    def __init__(self) -> None:
        raise OSError("cannot read config")


# ---------------------------------------------------------------------------
# TestAdapterRegistry
# ---------------------------------------------------------------------------


class TestAdapterRegistry:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters import AdapterRegistry
        from gxassessms.registry import DiscoveryError

        self.AdapterRegistry = AdapterRegistry
        self.DiscoveryError = DiscoveryError

    def test_frozen_prevents_field_reassignment(self) -> None:
        registry = self.AdapterRegistry(adapters={"a": _ValidAdapter}, validation_errors=[])
        with pytest.raises(FrozenInstanceError):
            registry.adapters = {}  # type: ignore[misc]

    def test_frozen_allows_contained_dict_mutation(self) -> None:
        """frozen=True only prevents field reassignment, not in-place mutation."""
        registry = self.AdapterRegistry(adapters={}, validation_errors=[])
        registry.adapters["a"] = _ValidAdapter  # Should not raise
        assert "a" in registry.adapters

    def test_names_returns_adapter_keys(self) -> None:
        registry = self.AdapterRegistry(
            adapters={"foo": _ValidAdapter, "bar": _ValidAdapter},
            validation_errors=[],
        )
        assert sorted(registry.names) == ["bar", "foo"]

    def test_get_returns_adapter_class(self) -> None:
        registry = self.AdapterRegistry(adapters={"x": _ValidAdapter}, validation_errors=[])
        assert registry.get("x") is _ValidAdapter

    def test_get_returns_none_for_missing(self) -> None:
        registry = self.AdapterRegistry(adapters={}, validation_errors=[])
        assert registry.get("missing") is None


# ---------------------------------------------------------------------------
# TestValidateAdapter
# ---------------------------------------------------------------------------


class TestValidateAdapter:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters import _validate_adapter

        self.validate = _validate_adapter

    def test_valid_adapter_returns_empty(self) -> None:
        assert self.validate("test", _ValidAdapter) == []

    def test_missing_attribute_returns_failure(self) -> None:
        failures = self.validate("test", _MissingParseAdapter)
        assert len(failures) == 1
        assert "parse" in failures[0]

    def test_type_error_during_instantiation(self) -> None:
        failures = self.validate("test", _TypeErrorOnInit)
        assert len(failures) == 1
        assert "TypeError" in failures[0]

    def test_import_error_during_instantiation(self) -> None:
        failures = self.validate("test", _ImportErrorOnInit)
        assert len(failures) == 1
        assert "ImportError" in failures[0]
        assert "missing dependency" in failures[0]

    def test_attribute_error_during_instantiation(self) -> None:
        failures = self.validate("test", _AttributeErrorOnInit)
        assert len(failures) == 1
        assert "AttributeError" in failures[0]

    def test_os_error_during_instantiation(self) -> None:
        failures = self.validate("test", _OSErrorOnInit)
        assert len(failures) == 1
        assert "OSError" in failures[0]

    def test_empty_tool_name_returns_failure(self) -> None:
        failures = self.validate("test", _EmptyToolNameAdapter)
        assert len(failures) == 1
        assert "non-empty string" in failures[0]

    def test_non_string_tool_name_returns_failure(self) -> None:
        failures = self.validate("test", _NonStringToolNameAdapter)
        assert len(failures) == 1
        assert "non-empty string" in failures[0]


# ---------------------------------------------------------------------------
# TestRequiredAttributesSync
# ---------------------------------------------------------------------------


class TestRequiredAttributesSync:
    def test_required_attributes_match_protocol(self) -> None:
        from gxassessms.adapters import _REQUIRED_ATTRIBUTES
        from gxassessms.core.contracts.types import ToolAdapter

        protocol_attrs = ToolAdapter.__protocol_attrs__
        assert protocol_attrs == _REQUIRED_ATTRIBUTES, (
            f"_REQUIRED_ATTRIBUTES and ToolAdapter.__protocol_attrs__ are out of sync. "
            f"Only in _REQUIRED_ATTRIBUTES: {_REQUIRED_ATTRIBUTES - protocol_attrs}. "
            f"Only in Protocol: {protocol_attrs - _REQUIRED_ATTRIBUTES}."
        )


# ---------------------------------------------------------------------------
# TestDiscoverAdapters
# ---------------------------------------------------------------------------


class TestDiscoverAdapters:
    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        from gxassessms.adapters import discover_adapters
        from gxassessms.registry import DiscoveryError, DiscoveryResult

        self.discover_adapters = discover_adapters
        self.DiscoveryResult = DiscoveryResult
        self.DiscoveryError = DiscoveryError

    @patch("gxassessms.adapters.discover_entry_points")
    def test_empty_entry_points(self, mock_discover: Any) -> None:
        mock_discover.return_value = self.DiscoveryResult(plugins={}, errors=[])
        registry = self.discover_adapters()
        assert registry.adapters == {}
        assert registry.validation_errors == []

    @patch("gxassessms.adapters.discover_entry_points")
    def test_valid_adapter_registered(self, mock_discover: Any) -> None:
        mock_discover.return_value = self.DiscoveryResult(
            plugins={"test": _ValidAdapter}, errors=[]
        )
        registry = self.discover_adapters()
        assert "test" in registry.adapters
        assert registry.adapters["test"] is _ValidAdapter
        assert len(registry.validation_errors) == 0

    @patch("gxassessms.adapters.discover_entry_points")
    def test_invalid_adapter_produces_error(self, mock_discover: Any) -> None:
        mock_discover.return_value = self.DiscoveryResult(
            plugins={"bad": _MissingParseAdapter}, errors=[]
        )
        registry = self.discover_adapters()
        assert "bad" not in registry.adapters
        assert len(registry.validation_errors) == 1
        assert registry.validation_errors[0].plugin_name == "bad"

    @patch("gxassessms.adapters.discover_entry_points")
    def test_mixed_valid_and_invalid(self, mock_discover: Any) -> None:
        mock_discover.return_value = self.DiscoveryResult(
            plugins={"good": _ValidAdapter, "bad": _MissingParseAdapter}, errors=[]
        )
        registry = self.discover_adapters()
        assert "good" in registry.adapters
        assert "bad" not in registry.adapters
        assert len(registry.validation_errors) == 1

    @patch("gxassessms.adapters.discover_entry_points")
    def test_load_errors_carried_forward(self, mock_discover: Any) -> None:
        load_error = self.DiscoveryError(
            plugin_name="broken", error_type="ImportError", message="no module"
        )
        mock_discover.return_value = self.DiscoveryResult(
            plugins={"good": _ValidAdapter}, errors=[load_error]
        )
        registry = self.discover_adapters()
        assert "good" in registry.adapters
        # Exactly 1 error: the carried-forward load error
        assert len(registry.validation_errors) == 1
        assert registry.validation_errors[0].plugin_name == "broken"


# ---------------------------------------------------------------------------
# TestAdapterRegistryStartupValidation
# ---------------------------------------------------------------------------


class TestAdapterRegistryStartupValidation:
    def test_rejects_duplicate_storage_slug(self) -> None:
        """Two adapters with the same storage_slug -> hard failure."""
        from gxassessms.adapters import _validate_registry_constraints

        class Adapter1:
            tool_name = "Adapter1"
            storage_slug = "duplicate"
            tool_source = ToolSource.SCUBAGEAR
            capabilities = frozenset()

        class Adapter2:
            tool_name = "Adapter2"
            storage_slug = "duplicate"
            tool_source = ToolSource.MAESTER
            capabilities = frozenset()

        with pytest.raises(ValueError, match=r"[Dd]uplicate.*storage_slug"):
            _validate_registry_constraints([Adapter1(), Adapter2()])

    def test_rejects_duplicate_tool_source(self) -> None:
        from gxassessms.adapters import _validate_registry_constraints

        class Adapter1:
            tool_name = "Adapter1"
            storage_slug = "adapter1"
            tool_source = ToolSource.SCUBAGEAR
            capabilities = frozenset()

        class Adapter2:
            tool_name = "Adapter2"
            storage_slug = "adapter2"
            tool_source = ToolSource.SCUBAGEAR
            capabilities = frozenset()

        with pytest.raises(ValueError, match=r"[Dd]uplicate.*tool_source"):
            _validate_registry_constraints([Adapter1(), Adapter2()])

    def test_rejects_missing_storage_slug(self) -> None:
        from gxassessms.adapters import _validate_registry_constraints

        class Adapter:
            tool_name = "BadAdapter"
            storage_slug = ""
            tool_source = ToolSource.SCUBAGEAR
            capabilities = frozenset()

        with pytest.raises(ValueError, match=r"empty.*storage_slug"):
            _validate_registry_constraints([Adapter()])

    def test_rejects_invalid_slug_format(self) -> None:
        from gxassessms.adapters import _validate_registry_constraints

        class Adapter:
            tool_name = "BadAdapter"
            storage_slug = "ScubaGear"  # uppercase
            tool_source = ToolSource.SCUBAGEAR
            capabilities = frozenset()

        with pytest.raises(ValueError, match=r"[Ss]lug.*format"):
            _validate_registry_constraints([Adapter()])


def test_ingest_capability_requires_method_and_schema_version() -> None:
    """Adapter declaring 'ingest' must have ingest_from_directory and default_schema_version."""
    from gxassessms.adapters import _validate_adapter

    class BadIngestAdapter:
        tool_name = "Bad"
        storage_slug = "bad"
        tool_source = ToolSource.SCUBAGEAR
        capabilities = frozenset({"collect", "ingest"})
        # Missing: default_schema_version, ingest_from_directory

        def check_prerequisites(self): pass
        def authenticate(self, config): pass
        def collect(self, config, auth): pass
        def validate_raw(self, manifest): pass
        def parse(self, manifest): pass
        def coverage(self, manifest): pass

    errors = _validate_adapter("bad-ingest", BadIngestAdapter)
    assert any("ingest" in str(e).lower() for e in errors)
