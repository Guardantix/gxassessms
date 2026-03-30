"""Main CLI entry point for mseco (Microsoft Ecosystem Assessment CLI).

Defines the top-level Click group with global options:
  --config      Path to engagement config YAML
  --log-level   Logging level (DEBUG, INFO, WARNING, ERROR)
  --log-format  Logging format (rich, json)
  --verbose/-v  Shortcut for --log-level DEBUG

Subcommands are registered by importing from cli/commands/.
Logging is configured once at CLI startup via setup_logging().
"""

from __future__ import annotations

import json as json_module
import logging
import sys
from datetime import UTC, datetime
from importlib.metadata import version as _pkg_version
from typing import Any

import click
from rich.logging import RichHandler


def _get_version() -> str:
    try:
        return _pkg_version("gxassessms")
    except Exception:
        return "0.0.0-unknown"


_MSECO_VERSION = _get_version()


# ---------------------------------------------------------------------------
# JSON log formatter (for --log-format json)
# ---------------------------------------------------------------------------


class JSONLogFormatter(logging.Formatter):
    """JSON structured log formatter for piping into log aggregation tools.

    Each log record becomes a single JSON line with timestamp, level,
    logger name, message, and any extra fields (tool name, engagement ID).
    """

    _json_format = True  # Marker for test detection

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Include extra fields if set by adapters/pipeline
        for key in ("tool_name", "engagement_id", "check_id", "stage"):
            value = getattr(record, key, None)
            if value is not None:
                entry[key] = value

        if record.exc_info and record.exc_info[1]:
            entry["exception"] = str(record.exc_info[1])

        return json_module.dumps(entry, default=str)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------


def setup_logging(
    log_level: str = "WARNING",
    log_format: str = "rich",
    verbose: bool = False,
) -> None:
    """Configure logging for the gxassessms package.

    Args:
        log_level: Python log level name.
        log_format: "rich" for Rich console handler, "json" for JSON lines.
        verbose: If True, overrides log_level to DEBUG.
    """
    effective_level = "DEBUG" if verbose else log_level
    level = getattr(logging, effective_level.upper(), logging.WARNING)

    root_logger = logging.getLogger("gxassessms")
    root_logger.setLevel(level)

    # Remove existing handlers to avoid duplicate output on re-invocation
    root_logger.handlers.clear()

    if log_format == "json":
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JSONLogFormatter())
    else:
        handler = RichHandler(
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )

    handler.setLevel(level)
    root_logger.addHandler(handler)


# ---------------------------------------------------------------------------
# Click group
# ---------------------------------------------------------------------------


@click.group(name="mseco")
@click.version_option(
    version=_MSECO_VERSION,
    prog_name="mseco",
)
@click.option(
    "--log-level",
    type=click.Choice(
        ["DEBUG", "INFO", "WARNING", "ERROR"],
        case_sensitive=False,
    ),
    default="WARNING",
    help="Set the logging level.",
)
@click.option(
    "--log-format",
    type=click.Choice(["rich", "json"], case_sensitive=False),
    default="rich",
    help="Logging output format. 'json' for structured JSON lines.",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=False,
    help="Shortcut for --log-level DEBUG.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    log_level: str,
    log_format: str,
    verbose: bool,
) -> None:
    """mseco -- Microsoft Ecosystem Assessment CLI.

    Run security assessments against Microsoft 365 and Azure tenants
    using multiple tools, consolidate findings, and generate reports.
    """
    ctx.ensure_object(dict)
    setup_logging(log_level=log_level, log_format=log_format, verbose=verbose)


# ---------------------------------------------------------------------------
# Register subcommands (deferred imports to keep this file lean)
# ---------------------------------------------------------------------------


def _register_commands() -> None:
    """Import and register all subcommand modules."""
    from gxassessms.cli.commands.adapters import adapters_group  # type: ignore[import-not-found]
    from gxassessms.cli.commands.analytics import analytics_group  # type: ignore[import-not-found]
    from gxassessms.cli.commands.collect import collect_cmd  # type: ignore[import-not-found]
    from gxassessms.cli.commands.consolidate import (  # type: ignore[import-not-found]
        consolidate_cmd,  # type: ignore[reportUnknownVariableType]
    )
    from gxassessms.cli.commands.engagement import (  # type: ignore[import-not-found]
        engagement_group,  # type: ignore[reportUnknownVariableType]
    )
    from gxassessms.cli.commands.preflight import preflight_cmd  # type: ignore[import-not-found]
    from gxassessms.cli.commands.replay import replay_cmd  # type: ignore[import-not-found]
    from gxassessms.cli.commands.report import report_cmd  # type: ignore[import-not-found]
    from gxassessms.cli.commands.review import review_cmd  # type: ignore[import-not-found]
    from gxassessms.cli.commands.run import run_cmd  # type: ignore[import-not-found]

    cli.add_command(run_cmd, "run")  # type: ignore[arg-type]
    cli.add_command(collect_cmd, "collect")  # type: ignore[arg-type]
    cli.add_command(consolidate_cmd, "consolidate")  # type: ignore[arg-type]
    cli.add_command(report_cmd, "report")  # type: ignore[arg-type]
    cli.add_command(replay_cmd, "replay")  # type: ignore[arg-type]
    cli.add_command(review_cmd, "review")  # type: ignore[arg-type]
    cli.add_command(engagement_group, "engagement")  # type: ignore[arg-type]
    cli.add_command(preflight_cmd, "preflight")  # type: ignore[arg-type]
    cli.add_command(adapters_group, "adapters")  # type: ignore[arg-type]
    cli.add_command(analytics_group, "analytics")  # type: ignore[arg-type]


try:
    _register_commands()
except ImportError as _e:
    # A broken command module should not prevent the whole CLI from starting.
    # The broken command simply won't be registered; its absence will surface
    # as "No such command" at invocation rather than a startup crash.
    logging.getLogger(__name__).warning("Failed to register one or more CLI commands: %s", _e)


def main() -> None:
    """Entry point for the mseco console script."""
    cli()
