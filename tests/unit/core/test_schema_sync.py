"""Schema sync tests -- verify adapter mapping coverage across all adapters.

Walks discovered adapters via discover_adapters() and asserts:
  - Every adapter instance exposes severity_map and category_map properties
  - Every mapped value is a valid Severity/Category enum member
  - Every Severity/Category enum value is covered by at least one adapter
  - constants.json bridge output covers every enum value

This catches drift between enum definitions and adapter implementations.
"""

from __future__ import annotations

import contextlib
from typing import Any

import pytest

from gxassessms.adapters import discover_adapters
from gxassessms.core.domain.constants import ADAPTER_PLACEHOLDERS
from gxassessms.core.domain.enums import Category, Severity, ToolSource
from gxassessms.reporting.constants_bridge import generate_constants_dict

# Helpers ---------------------------------------------------------------

# Mirrors the exception tuple in src/gxassessms/adapters/__init__.py
# _validate_adapter -- instantiation failures that the production validator
# also tolerates during smoke-test registration. Aligning the two lists
# prevents the schema-sync suite from crashing on an adapter that production
# accepts, and prevents drift if the production tolerances change.
_ADAPTER_INIT_TOLERATED = (
    TypeError,
    ValueError,
    RuntimeError,
    ImportError,
    AttributeError,
    OSError,
)


def _collect_severity_values(adapters: list[Any]) -> set[Severity]:
    """Union of all severity values mapped by any adapter's severity_map.

    Invalid values are suppressed here because
    test_no_invalid_severity_values_in_any_map is the canonical check for
    garbage values; this helper only needs the union of the *valid* subset.
    """
    values: set[Severity] = set()
    for adapter in adapters:
        sev_map = getattr(adapter, "severity_map", {})
        for v in sev_map.values():
            if isinstance(v, Severity):
                values.add(v)
            else:
                with contextlib.suppress(ValueError, KeyError):
                    values.add(Severity(v))
    return values


def _collect_category_values(adapters: list[Any]) -> set[Category]:
    """Union of all category values mapped by any adapter's category_map.

    See _collect_severity_values for the rationale behind the suppress.
    """
    values: set[Category] = set()
    for adapter in adapters:
        cat_map = getattr(adapter, "category_map", {})
        for v in cat_map.values():
            if isinstance(v, Category):
                values.add(v)
            else:
                with contextlib.suppress(ValueError, KeyError):
                    values.add(Category(v))
    return values


# Fixtures --------------------------------------------------------------


@pytest.fixture(scope="module")
def adapters() -> list[Any]:
    """Instantiate every discovered adapter, failing fast if none exist.

    Module-scoped so each test gets the same list without re-discovering.
    Fails loudly if no adapters are discovered -- without this guard the
    iterating tests below would silently pass on an empty list.
    """
    registry = discover_adapters()
    instances: list[Any] = []
    for _name, cls in registry.adapters.items():
        try:
            instances.append(cls())
        except _ADAPTER_INIT_TOLERATED:
            continue
    assert instances, (
        "No adapters discovered. Schema sync tests are only meaningful when "
        "adapter entry points are registered. Check pyproject.toml and that "
        "the package was installed in editable mode."
    )
    return instances


# Tests -----------------------------------------------------------------


class TestAdapterDiscovery:
    """At least one adapter must be discovered for these tests to be meaningful."""

    def test_adapters_discovered(self, adapters: list[Any]) -> None:
        assert len(adapters) >= 1


class TestAdapterMappingProperties:
    """Every discovered adapter exposes severity_map and category_map."""

    def test_every_adapter_has_severity_map(self, adapters: list[Any]) -> None:
        for adapter in adapters:
            assert hasattr(adapter, "severity_map"), (
                f"{type(adapter).__name__} missing severity_map property"
            )
            sev_map = adapter.severity_map
            assert isinstance(sev_map, dict), (
                f"{type(adapter).__name__}.severity_map must be a dict"
            )

    def test_every_adapter_has_category_map(self, adapters: list[Any]) -> None:
        for adapter in adapters:
            assert hasattr(adapter, "category_map"), (
                f"{type(adapter).__name__} missing category_map property"
            )
            cat_map = adapter.category_map
            assert isinstance(cat_map, dict), (
                f"{type(adapter).__name__}.category_map must be a dict"
            )


class TestSeverityCoverage:
    """Every Severity value must be mapped by at least one adapter."""

    def test_all_severities_covered_by_at_least_one_adapter(self, adapters: list[Any]) -> None:
        mapped = _collect_severity_values(adapters)
        missing = set(Severity) - mapped
        assert not missing, (
            f"These Severity values are not mapped by any adapter's "
            f"severity_map: {sorted(s.name for s in missing)}. Add them to "
            f"at least one adapter's mappings."
        )

    def test_no_invalid_severity_values_in_any_map(self, adapters: list[Any]) -> None:
        for adapter in adapters:
            sev_map = getattr(adapter, "severity_map", {})
            for key, value in sev_map.items():
                if not isinstance(value, Severity):
                    try:
                        Severity(value)
                    except ValueError, KeyError:
                        pytest.fail(
                            f"{type(adapter).__name__}.severity_map[{key!r}] "
                            f"= {value!r} is not a valid Severity member."
                        )


class TestCategoryCoverage:
    """Every Category value must be mapped by at least one adapter."""

    def test_all_categories_covered_by_at_least_one_adapter(self, adapters: list[Any]) -> None:
        mapped = _collect_category_values(adapters)
        missing = set(Category) - mapped
        assert not missing, (
            f"These Category values are not mapped by any adapter's "
            f"category_map: {sorted(c.name for c in missing)}. Add them to "
            f"at least one adapter's mappings."
        )

    def test_no_invalid_category_values_in_any_map(self, adapters: list[Any]) -> None:
        for adapter in adapters:
            cat_map = getattr(adapter, "category_map", {})
            for key, value in cat_map.items():
                if not isinstance(value, Category):
                    try:
                        Category(value)
                    except ValueError, KeyError:
                        pytest.fail(
                            f"{type(adapter).__name__}.category_map[{key!r}] "
                            f"= {value!r} is not a valid Category member."
                        )


class TestToolSourceAdapterRegistration:
    """Every non-placeholder ToolSource should have exactly one registered adapter."""

    def test_every_implemented_tool_source_has_adapter(self, adapters: list[Any]) -> None:
        registered_sources = {getattr(a, "tool_source", None) for a in adapters} - {None}
        for source in ToolSource:
            if source == ToolSource.MANUAL:
                continue  # MANUAL is operator-injected, not an adapter
            if source.value in ADAPTER_PLACEHOLDERS:
                continue
            assert source in registered_sources, (
                f"ToolSource.{source.name} has no registered adapter. "
                f"Either add it to ADAPTER_PLACEHOLDERS or register an adapter."
            )

    def test_placeholder_set_is_valid(self) -> None:
        assert isinstance(ADAPTER_PLACEHOLDERS, frozenset)
        valid_values = {ts.value for ts in ToolSource}
        for placeholder in ADAPTER_PLACEHOLDERS:
            assert isinstance(placeholder, str)
            assert placeholder in valid_values, (
                f"ADAPTER_PLACEHOLDERS contains {placeholder!r} which is not "
                f"a valid ToolSource value."
            )


class TestConstantsBridgeSync:
    """constants.json (for the report payload) covers every domain enum."""

    def test_all_severities_in_constants_bridge(self) -> None:
        constants = generate_constants_dict()
        severity_order = constants["severity_order"]
        for severity in Severity:
            assert severity.name in severity_order, (
                f"Severity.{severity.name} missing from constants severity_order."
            )

    def test_all_categories_in_constants_bridge(self) -> None:
        constants = generate_constants_dict()
        category_names = constants["category_display_names"]
        for category in Category:
            assert category.name in category_names, (
                f"Category.{category.name} missing from constants category_display_names."
            )

    def test_severity_colors_complete(self) -> None:
        constants = generate_constants_dict()
        colors = constants["severity_colors"]
        for severity in Severity:
            assert severity.name in colors, (
                f"Severity.{severity.name} missing from severity_colors."
            )
            color_value = colors[severity.name]
            assert isinstance(color_value, str)
            assert color_value
