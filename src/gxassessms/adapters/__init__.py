"""Adapter registry -- discovers and validates ToolAdapter implementations via entry points.

Uses the generic registry.discover_entry_points() for loading, then applies
adapter-specific validation:

1. Import test: handled by registry.py
2. Attribute check: does it have required attributes?
3. Smoke test: does tool_name return a non-empty string?

Invalid adapters are logged as warnings and excluded from the active registry.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from gxassessms.registry import DiscoveryError, discover_entry_points

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ADAPTER_GROUP = "gxassessms.adapters"

_REQUIRED_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "tool_name",
        "capabilities",
        "check_prerequisites",
        "authenticate",
        "collect",
        "parse",
        "coverage",
        "validate_raw",
    }
)

# ---------------------------------------------------------------------------
# Registry dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdapterRegistry:
    """Holds validated adapter classes discovered from entry points.

    Attributes:
        adapters:          Validated adapter classes keyed by entry-point name.
        validation_errors: Errors accumulated during discovery and validation.
    """

    adapters: dict[str, Any] = field(default_factory=dict[str, Any])
    validation_errors: list[DiscoveryError] = field(default_factory=list[DiscoveryError])

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def names(self) -> list[str]:
        """Names of all successfully validated adapters."""
        return list(self.adapters.keys())

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------

    def get(self, name: str) -> Any | None:
        """Return the adapter class for *name*, or None if not present."""
        return self.adapters.get(name)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_adapter(name: str, adapter_class: Any) -> list[str]:
    """Validate that *adapter_class* satisfies the ToolAdapter Protocol.

    Checks:
    1. All required attributes are present on the class.
    2. The class can be instantiated.
    3. ``tool_name`` on an instance returns a non-empty string.

    Args:
        name:          The entry-point name (used only for error messages).
        adapter_class: The class object loaded from the entry point.

    Returns:
        A list of failure messages. An empty list means the adapter is valid.
    """
    failures: list[str] = []

    # Protocol check -- all required attributes must exist
    missing = _REQUIRED_ATTRIBUTES - set(dir(adapter_class))
    if missing:
        sorted_missing = sorted(missing)
        failures.append(f"Adapter {name!r} is missing required attributes: {sorted_missing}")
        return failures  # No point trying instantiation if Protocol is incomplete

    # Smoke test -- instantiate and verify tool_name is a non-empty string
    try:
        instance = adapter_class()
    except (TypeError, ValueError, RuntimeError, ImportError, AttributeError, OSError) as exc:
        failures.append(f"Adapter {name!r} raised {type(exc).__name__} during instantiation: {exc}")
        return failures

    try:
        tool_name_value = instance.tool_name
    except AttributeError as exc:
        failures.append(f"Adapter {name!r} raised {type(exc).__name__} accessing tool_name: {exc}")
        return failures

    if not isinstance(tool_name_value, str) or not tool_name_value.strip():
        failures.append(
            f"Adapter {name!r} tool_name must be a non-empty string; got {tool_name_value!r}"
        )

    return failures


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discover_adapters() -> AdapterRegistry:
    """Discover and validate all adapters registered in the entry-point group.

    Steps:
    1. Call ``discover_entry_points(ADAPTER_GROUP)`` to load raw plugins.
    2. Carry forward any import/attribute errors from that discovery pass.
    3. Validate each loaded plugin via ``_validate_adapter``.
    4. Valid adapters are stored in ``AdapterRegistry.adapters``.
       Invalid adapters produce a ``DiscoveryError`` in
       ``AdapterRegistry.validation_errors``.

    Returns:
        A fully-populated ``AdapterRegistry``.
    """
    discovery = discover_entry_points(ADAPTER_GROUP)

    adapters: dict[str, Any] = {}
    validation_errors: list[DiscoveryError] = list(discovery.errors)

    # Validate each successfully loaded plugin
    for adapter_name, adapter_class in discovery.plugins.items():
        failures = _validate_adapter(adapter_name, adapter_class)

        if failures:
            for message in failures:
                logger.warning("Adapter %r failed validation: %s", adapter_name, message)
                validation_errors.append(
                    DiscoveryError(
                        plugin_name=adapter_name,
                        error_type="ValidationError",
                        message=message,
                    )
                )
        else:
            adapters[adapter_name] = adapter_class
            logger.debug("Registered adapter %r", adapter_name)

    # Summary log
    valid_count = len(adapters)
    error_count = len(validation_errors)
    if valid_count or error_count:
        logger.info(
            "Adapter discovery complete: %d valid, %d error(s)",
            valid_count,
            error_count,
        )
    else:
        logger.debug(
            "Adapter discovery complete: no adapters registered under %r",
            ADAPTER_GROUP,
        )

    return AdapterRegistry(adapters=adapters, validation_errors=validation_errors)
