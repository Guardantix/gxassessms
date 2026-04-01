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

    from gxassessms.persistence import ArtifactManager

    return Orchestrator(
        engagement_repo=EngagementRepo(db),
        event_repo=EventRepo(db),
        finding_repo=FindingRepo(db),
        coverage_repo=CoverageRepo(db),
        lock=EngagementLock(engagements_root),
        db=db,
        artifact_manager=ArtifactManager(engagements_root),
    )


def get_engagements_root() -> Path:
    """Return the engagements root directory, creating it if needed."""
    from gxassessms.persistence import get_default_data_dir

    root = get_default_data_dir() / "engagements"
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise GxAssessError(
            f"Failed to create engagements directory: {e}. "
            "Check disk space and directory permissions."
        ) from e
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
        except (TypeError, ValueError, RuntimeError, FileNotFoundError) as exc:
            logger.warning("Failed to instantiate adapter %s: %s", name, exc)
    return instances


def filter_and_validate_adapters(config: Any, adapters: list[Any]) -> list[Any]:
    """Filter adapters to enabled tools and validate coverage.

    Returns filtered adapter list. Raises SystemExit(1) with per-tool
    error messages if any enabled tool has no matching adapter.
    """
    if not config.tools:
        return adapters

    enabled_tool_names = {name.lower() for name, tc in config.tools.items() if tc.enabled}
    filtered = [a for a in adapters if getattr(a, "tool_name", "").lower() in enabled_tool_names]
    discovered_names = {getattr(a, "tool_name", "").lower() for a in filtered}
    missing = enabled_tool_names - discovered_names
    if missing:
        from rich.console import Console

        console = Console(stderr=True)
        for name in sorted(missing):
            console.print(
                f"[bright_red]Error:[/bright_red] Tool '{name}' is enabled in config "
                f"but no adapter is installed. Install gxassessms-{name}."
            )
        raise SystemExit(1)
    return filtered


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
        except (TypeError, ValueError, RuntimeError, FileNotFoundError) as exc:
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


def discover_plugin(group: str, *, name: str | None = None) -> Any | None:
    """Discover and instantiate a plugin from an entry point group.

    Selection logic:
    1. If *name* is given, only that entry point is loaded.
    2. Otherwise, plugins are sorted by optional ``priority`` class
       attribute (descending, default 0). Ties broken by discovery order.

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

    if name is not None:
        cls = result.get(name)
        if cls is None:
            logger.warning(
                "Requested plugin %r not found in group %s. Available: %s",
                name,
                group,
                result.names,
            )
            return None
        try:
            return cls()
        except (TypeError, ValueError, RuntimeError, FileNotFoundError) as exc:
            logger.warning("Failed to instantiate %s plugin %s: %s", group, name, exc)
            return None

    if not result.names:
        return None

    # Sort by priority (descending). getattr(None, ...) is safe -- result.get
    # returns None for failed loads, getattr(None, "priority", 0) -> 0.
    sorted_names = sorted(
        result.names,
        key=lambda n: getattr(result.get(n), "priority", 0),
        reverse=True,
    )

    for candidate_name in sorted_names:
        cls = result.get(candidate_name)
        if cls is not None:
            try:
                return cls()
            except (TypeError, ValueError, RuntimeError, FileNotFoundError) as exc:
                logger.warning(
                    "Failed to instantiate %s plugin %s: %s",
                    group,
                    candidate_name,
                    exc,
                )
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
            except (TypeError, ValueError, RuntimeError, FileNotFoundError) as exc:
                logger.warning("Failed to instantiate %s plugin %s: %s", group, name, exc)
    return instances


def _load_policy_rules(filename: str) -> dict[str, Any]:
    """Load a YAML rules file bundled with the gxassessms.policy package.

    Works in both editable installs and wheels (uses importlib.resources).
    Raises ConfigError on missing or malformed file.
    """
    import importlib.resources

    import yaml

    from gxassessms.core.contracts.errors import ConfigError

    try:
        pkg = importlib.resources.files("gxassessms.policy")
        text = (pkg / "rules" / filename).read_text(encoding="utf-8")
        return yaml.safe_load(text)  # type: ignore[no-any-return]
    except (FileNotFoundError, OSError) as exc:
        raise ConfigError(
            f"Policy rules file not found: {filename}. "
            "Package may be misconfigured (missing YAML artifacts in wheel)."
        ) from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse policy rules file {filename}: {exc}") from exc


def build_normalization_policy() -> Any:
    """Return a NormalizationPolicy for the CLI.

    Checks gxassessms.policies entry point for a 'normalization' override.
    Falls back to DefaultNormalizationPolicy on missing override or failure.
    """
    from gxassessms.policy.normalization import DefaultNormalizationPolicy
    from gxassessms.registry import discover_entry_points

    result = discover_entry_points("gxassessms.policies")
    for err in result.errors:
        logger.warning(
            "Plugin discovery error in gxassessms.policies: %s: %s",
            err.plugin_name,
            err.message,
        )
    rules = _load_policy_rules("normalization.yaml")
    cls = result.get("normalization")
    if cls is not None:
        try:
            return cls(rules=rules)
        except (TypeError, ValueError) as exc:
            logger.warning(
                "Failed to instantiate normalization policy %s: %s; "
                "falling back to DefaultNormalizationPolicy",
                getattr(cls, "__name__", cls),
                exc,
            )
    return DefaultNormalizationPolicy(rules=rules)


def build_consolidation_rule() -> Any:
    """Return a ConsolidationRule for the CLI.

    Checks gxassessms.consolidation_rules entry point for a 'default' override.
    Falls back to DefaultConsolidationRule on missing override or failure.
    """
    from gxassessms.consolidation.rules import DefaultConsolidationRule
    from gxassessms.policy.consolidation import DefaultConsolidationPolicy
    from gxassessms.registry import discover_entry_points

    result = discover_entry_points("gxassessms.consolidation_rules")
    for err in result.errors:
        logger.warning(
            "Plugin discovery error in gxassessms.consolidation_rules: %s: %s",
            err.plugin_name,
            err.message,
        )
    consolidation_rules = _load_policy_rules("consolidation.yaml")
    policy = DefaultConsolidationPolicy(rules=consolidation_rules)
    cls = result.get("default")
    if cls is not None:
        try:
            return cls(policy=policy)
        except (TypeError, ValueError) as exc:
            logger.warning(
                "Failed to instantiate consolidation rule %s: %s; "
                "falling back to DefaultConsolidationRule",
                getattr(cls, "__name__", cls),
                exc,
            )
    return DefaultConsolidationRule(policy=policy)
