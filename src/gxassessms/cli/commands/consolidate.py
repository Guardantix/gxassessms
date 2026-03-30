"""mseco consolidate -- re-run normalization and deduplication.

Usage:
    mseco consolidate <config.yaml>
    mseco consolidate --reparse <config.yaml>

Re-runs normalization and dedup from persisted raw output. Does not
re-execute tools or re-parse raw output unless --reparse is provided.
Useful when normalization logic or cross-reference mappings change.
"""

from __future__ import annotations

import logging
from pathlib import Path

import click

import gxassessms.cli._helpers as _helpers
from gxassessms.cli.output import console
from gxassessms.core.config.config import load_config, validate_config
from gxassessms.core.contracts.errors import ConfigError, GxAssessError

logger = logging.getLogger(__name__)


@click.command("consolidate")
@click.argument(
    "config_path",
    type=click.Path(exists=False),
)
@click.option(
    "--engagement-id",
    required=True,
    help="ID of the engagement to consolidate (required -- consolidate operates on existing data).",
)
@click.option(
    "--reparse",
    is_flag=True,
    default=False,
    help="Re-parse raw output before normalizing (use when parser logic changes).",
)
def consolidate_cmd(config_path: str, engagement_id: str, reparse: bool) -> None:
    """Re-run normalization and deduplication from persisted raw output.

    Does not re-execute tools. Starts from PARSE (with --reparse) or
    NORMALIZE (default). Useful when normalization logic or
    cross-reference mappings change.

    Requires --engagement-id because consolidate operates on an existing
    engagement's persisted raw output.
    """
    path = Path(config_path)
    if not path.exists():
        console.print(f"[bright_red]Error:[/bright_red] Config file not found: {path}")
        raise SystemExit(1)

    try:
        config = load_config(path)
    except ConfigError as e:
        console.print(f"[bright_red]Config error:[/bright_red] {e}")
        raise SystemExit(1) from None

    errors, warnings = validate_config(config)
    for w in warnings:
        console.print(f"[yellow]Warning:[/yellow] {w}")
    if errors:
        for e in errors:
            console.print(f"[bright_red]Error:[/bright_red] {e}")
        raise SystemExit(1)

    try:
        from gxassessms.pipeline.stages import Stage

        orchestrator = _helpers.build_orchestrator()
        adapters = _helpers.discover_cli_adapters()

        start_stage = Stage.PARSE if reparse else Stage.NORMALIZE
        console.print(
            f"[bold]Consolidating engagement {engagement_id} "
            f"from stage {start_stage.value}...[/bold]"
        )

        orchestrator.run_from(
            engagement_id=engagement_id,
            config=config,
            start_stage=start_stage,
            adapters=adapters,
            normalization_policy=_helpers.discover_plugin("gxassessms.policies"),
            consolidation_rule=_helpers.discover_plugin("gxassessms.consolidation_rules"),
            qa_strategy=_helpers.discover_plugin("gxassessms.qa_strategies"),
            renderers=[],
        )

        console.print("\n[bright_green]Consolidation complete.[/bright_green]")

    except GxAssessError as e:
        console.print(f"\n[bright_red]Consolidation failed:[/bright_red] {e}")
        logger.error("Consolidation failed: %s", e)
        raise SystemExit(1) from None
