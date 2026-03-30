"""mseco analytics -- analytics commands (delegated to private package).

Subcommands:
    mseco analytics tuning    -- Show tuning recommendations
    mseco analytics cost      -- Token usage and cost per engagement
    mseco analytics coverage  -- Tool coverage across engagements

All subcommands delegate to the private package (gxassessms-guardantix)
via the gxassessms.analytics entry point group. If the private package
is not installed, shows a message directing the user to install it.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import Any

import click

from gxassessms.cli.output import console

logger = logging.getLogger(__name__)

_PRIVATE_PKG_MSG = (
    "[yellow]Analytics requires the Guardantix private package.[/yellow]\n"
    "\n"
    "Analytics features (tuning recommendations, cost tracking, and\n"
    "coverage analysis) are provided by gxassessms-guardantix.\n"
    "\n"
    "Install gxassessms-guardantix to enable."
)


def _get_analytics_plugin() -> Any | None:
    """Load the analytics plugin from the private package.

    Returns the analytics instance, or None if not installed.
    """
    eps = entry_points(group="gxassessms.analytics")
    ep_list = list(eps)
    if not ep_list:
        return None

    try:
        cls = ep_list[0].load()
        return cls()
    except Exception as e:
        logger.warning(
            "Analytics plugin failed to load from '%s': %s",
            "gxassessms.analytics",
            e,
            exc_info=True,
        )
        return None


@click.group("analytics")
def analytics_group() -> None:
    """Analytics and insight commands (requires gxassessms-guardantix)."""
    pass


@analytics_group.command("tuning")
def tuning_cmd() -> None:
    """Show tuning recommendations based on engagement history.

    Analyzes override patterns, dedup hit rates, and AI prompt
    quality to produce actionable recommendations for improving
    assessment accuracy.

    Requires gxassessms-guardantix.
    """
    plugin = _get_analytics_plugin()
    if plugin is None:
        console.print(_PRIVATE_PKG_MSG)
        raise SystemExit(1)

    try:
        plugin.show_tuning()
    except Exception as e:
        console.print(f"[bright_red]Analytics error:[/bright_red] {e}")
        logger.error("Analytics tuning failed: %s", e)
        raise SystemExit(1) from None


@analytics_group.command("cost")
def cost_cmd() -> None:
    """Show token usage and cost per engagement.

    Reports AI token consumption, cost estimates, and per-QA-task
    breakdowns for completed engagements.

    Requires gxassessms-guardantix.
    """
    plugin = _get_analytics_plugin()
    if plugin is None:
        console.print(_PRIVATE_PKG_MSG)
        raise SystemExit(1)

    try:
        plugin.show_cost()
    except Exception as e:
        console.print(f"[bright_red]Analytics error:[/bright_red] {e}")
        logger.error("Analytics cost failed: %s", e)
        raise SystemExit(1) from None


@analytics_group.command("coverage")
def coverage_cmd() -> None:
    """Show tool coverage across engagements.

    Reports which tools contributed findings, adapter performance
    (execution time, failure rates), and coverage gaps across
    assessment history.

    Requires gxassessms-guardantix.
    """
    plugin = _get_analytics_plugin()
    if plugin is None:
        console.print(_PRIVATE_PKG_MSG)
        raise SystemExit(1)

    try:
        plugin.show_coverage()
    except Exception as e:
        console.print(f"[bright_red]Analytics error:[/bright_red] {e}")
        logger.error("Analytics coverage failed: %s", e)
        raise SystemExit(1) from None
