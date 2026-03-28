"""Generic entry-point discovery utilities.

Shared by all plugin types: adapters, renderers, QA strategies, credential
providers, consolidation rules, and policies. Each plugin type uses a
different entry-point group name (e.g., 'gxassessms.adapters',
'gxassessms.renderers'), but the discovery mechanics are the same.

This module does NOT perform plugin-type-specific validation (e.g., Protocol
checks). That is the responsibility of the specific registry module for each
plugin type (e.g., adapters/__init__.py).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DiscoveryError:
    """Records a failure that occurred while loading a single entry point.

    Attributes:
        plugin_name: The entry-point name that failed to load.
        error_type:  The exception class name (e.g. 'ImportError').
        message:     Human-readable description of the failure.
    """

    plugin_name: str
    error_type: str
    message: str


@dataclass
class DiscoveryResult:
    """Outcome of a single entry-point group discovery pass.

    Attributes:
        plugins: Mapping of entry-point name -> loaded object for every
                 entry point that loaded successfully.
        errors:  One DiscoveryError per entry point that failed to load.
    """

    plugins: dict[str, Any] = field(default_factory=dict[str, Any])
    errors: list[DiscoveryError] = field(default_factory=list[DiscoveryError])

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def names(self) -> list[str]:
        """Names of all successfully loaded plugins."""
        return list(self.plugins.keys())

    @property
    def has_errors(self) -> bool:
        """True if at least one entry point failed to load."""
        return bool(self.errors)

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------

    def get(self, name: str) -> Any | None:
        """Return the loaded plugin object for *name*, or None if not present."""
        return self.plugins.get(name)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discover_entry_points(group: str) -> DiscoveryResult:
    """Load all entry points registered under *group*.

    Each entry point is loaded via ``ep.load()``. Failures are caught
    individually so that one broken plugin does not prevent the others from
    loading. Only ``ImportError`` and ``AttributeError`` are caught; all
    other exceptions propagate normally.

    Args:
        group: The entry-point group name (e.g. 'gxassessms.adapters').

    Returns:
        A DiscoveryResult containing the successfully loaded plugins and
        a DiscoveryError for each plugin that failed to load.
    """
    plugins: dict[str, Any] = {}
    errors: list[DiscoveryError] = []

    eps = entry_points(group=group)

    for ep in eps:
        try:
            obj = ep.load()
        except ImportError as exc:
            logger.warning("Plugin %r failed to load (ImportError): %s", ep.name, exc)
            errors.append(
                DiscoveryError(
                    plugin_name=ep.name,
                    error_type="ImportError",
                    message=str(exc),
                )
            )
        except AttributeError as exc:
            logger.warning("Plugin %r failed to load (AttributeError): %s", ep.name, exc)
            errors.append(
                DiscoveryError(
                    plugin_name=ep.name,
                    error_type="AttributeError",
                    message=str(exc),
                )
            )
        else:
            plugins[ep.name] = obj
            logger.debug("Loaded plugin %r from group %r", ep.name, group)

    return DiscoveryResult(plugins=plugins, errors=errors)
