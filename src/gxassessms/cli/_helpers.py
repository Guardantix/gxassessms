"""Shared CLI factories: orchestrator wiring and plugin discovery.

All heavy imports are deferred to function bodies to avoid import-time
side effects. Commands import from here instead of cross-importing from
each other.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from gxassessms.core.contracts.errors import GxAssessError

logger = logging.getLogger(__name__)


def build_orchestrator() -> Any:
    """Build an Orchestrator with all dependencies.

    Initializes the database, creates repositories, and wires them
    into an Orchestrator instance.
    """
    from gxassessms.persistence import (
        CoverageRepo,
        DatabaseManager,
        EngagementRepo,
        EventRepo,
        FindingRepo,
        get_default_data_dir,
    )
    from gxassessms.pipeline.orchestrator import Orchestrator
    from gxassessms.pipeline.state import EngagementLock

    try:
        db = DatabaseManager()
        db.initialize()
        engagements_root = get_default_data_dir() / "engagements"
        engagements_root.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise GxAssessError(
            f"Failed to initialize data directory: {e}. Check disk space and directory permissions."
        ) from e

    return Orchestrator(
        engagement_repo=EngagementRepo(db),
        event_repo=EventRepo(db),
        finding_repo=FindingRepo(db),
        coverage_repo=CoverageRepo(db),
        lock=EngagementLock(engagements_root),
        db=db,
    )


def get_engagements_root() -> Path:
    """Return the engagements root directory, creating it if needed."""
    from gxassessms.persistence import get_default_data_dir

    root = get_default_data_dir() / "engagements"
    root.mkdir(parents=True, exist_ok=True)
    return root


def get_engagement_repo() -> Any:
    """Build and return an EngagementRepo instance."""
    from gxassessms.persistence import DatabaseManager, EngagementRepo

    try:
        db = DatabaseManager()
        db.initialize()
    except OSError as e:
        raise GxAssessError(
            f"Failed to initialize database: {e}. Check disk space and directory permissions."
        ) from e
    return EngagementRepo(db)


def get_artifact_manager() -> Any:
    """Build and return an ArtifactManager instance."""
    from gxassessms.persistence import ArtifactManager

    return ArtifactManager(get_engagements_root())


def discover_cli_adapters() -> list[Any]:
    """Discover and instantiate registered ToolAdapter implementations.

    Uses AdapterRegistry from gxassessms.adapters (which validates
    Protocol compliance). Returns instantiated adapter objects.
    """
    from gxassessms.adapters import discover_adapters

    registry = discover_adapters()
    for err in registry.validation_errors:
        logger.warning("Adapter validation error: %s: %s", err.plugin_name, err.message)
    # Registry stores classes; instantiate for pipeline use
    instances: list[Any] = []
    for name, cls in registry.adapters.items():
        try:
            instances.append(cls())
        except (TypeError, ValueError, RuntimeError) as exc:
            logger.warning("Failed to instantiate adapter %s: %s", name, exc)
    return instances


def discover_adapter_metadata() -> list[dict[str, Any]]:
    """Discover adapters and return their metadata dicts for display.

    Returns a list of dicts with keys: name, entry_point, capabilities, status.
    """
    from gxassessms.adapters import discover_adapters

    registry = discover_adapters()
    result: list[dict[str, Any]] = []

    for name, cls in registry.adapters.items():
        try:
            instance = cls()
            caps: frozenset[str] = getattr(instance, "capabilities", frozenset())
            result.append(
                {
                    "name": getattr(instance, "tool_name", name),
                    "entry_point": name,
                    "capabilities": sorted(caps),
                    "status": "OK",
                }
            )
        except (TypeError, ValueError, RuntimeError) as exc:
            result.append(
                {
                    "name": name,
                    "entry_point": name,
                    "capabilities": [],
                    "status": f"FAIL: {exc}",
                }
            )

    for err in registry.validation_errors:
        result.append(
            {
                "name": err.plugin_name,
                "entry_point": err.plugin_name,
                "capabilities": [],
                "status": f"FAIL: {err.message}",
            }
        )

    return result


def discover_plugin(group: str) -> Any | None:
    """Discover and instantiate the first plugin from an entry point group.

    Returns an instance, or None if nothing found. Used for singleton
    plugins like normalization policy or QA strategy.
    """
    from gxassessms.registry import discover_entry_points

    result = discover_entry_points(group)
    for err in result.errors:
        logger.warning(
            "Plugin discovery error in %s: %s: %s",
            group,
            err.plugin_name,
            err.message,
        )
    if result.names:
        name = result.names[0]
        cls = result.get(name)
        if cls is not None:
            try:
                return cls()
            except (TypeError, ValueError, RuntimeError) as exc:
                logger.warning("Failed to instantiate %s plugin %s: %s", group, name, exc)
    return None


def discover_all_plugins(group: str) -> list[Any]:
    """Discover and instantiate all plugins from an entry point group.

    Used for renderers where multiple implementations may be registered.
    """
    from gxassessms.registry import discover_entry_points

    result = discover_entry_points(group)
    for err in result.errors:
        logger.warning(
            "Plugin discovery error in %s: %s: %s",
            group,
            err.plugin_name,
            err.message,
        )
    instances: list[Any] = []
    for name in result.names:
        cls = result.get(name)
        if cls is not None:
            try:
                instances.append(cls())
            except (TypeError, ValueError, RuntimeError) as exc:
                logger.warning("Failed to instantiate %s plugin %s: %s", group, name, exc)
    return instances
