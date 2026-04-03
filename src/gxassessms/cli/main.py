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
        from gxassessms import __version__

        return __version__


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


def _try_register(module_path: str, symbol: str, name: str) -> None:
    """Import a single command symbol and register it; log and skip on ImportError.

    Each command is registered independently so a missing module only omits
    that command -- it does not prevent the rest from loading.
    """
    _log = logging.getLogger(__name__)
    try:
        mod = __import__(module_path, fromlist=[symbol])
        cmd = getattr(mod, symbol)
        cli.add_command(cmd, name)  # type: ignore[arg-type]
    except ImportError as _e:
        _log.warning("Skipping CLI command '%s': %s", name, _e)
    except AttributeError as _e:
        _log.error(
            "CLI command '%s' registered with missing symbol '%s' in '%s': %s",
            name,
            symbol,
            module_path,
            _e,
        )


def _register_commands() -> None:
    """Import and register all subcommand modules, one at a time."""
    _try_register("gxassessms.cli.commands.run", "run_cmd", "run")
    _try_register("gxassessms.cli.commands.collect", "collect_cmd", "collect")
    _try_register("gxassessms.cli.commands.consolidate", "consolidate_cmd", "consolidate")
    _try_register("gxassessms.cli.commands.report", "report_cmd", "report")
    _try_register("gxassessms.cli.commands.replay", "replay_cmd", "replay")
    _try_register("gxassessms.cli.commands.review", "review_cmd", "review")
    _try_register("gxassessms.cli.commands.engagement", "engagement_group", "engagement")
    _try_register("gxassessms.cli.commands.preflight", "preflight_cmd", "preflight")
    _try_register("gxassessms.cli.commands.adapters", "adapters_group", "adapters")
    _try_register("gxassessms.cli.commands.analytics", "analytics_group", "analytics")
    _try_register("gxassessms.cli.commands.compute_hash", "compute_hash_cmd", "compute-module-hash")


_register_commands()


def main() -> None:
    """Entry point for the mseco console script."""
    cli()
