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
    type=click.Path(exists=True, dir_okay=False),
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
    help="Re-run from raw tool output (re-parse + re-normalize + re-consolidate). "
    "Default re-consolidates from persisted parsed findings.",
)
@click.option(
    "--qa-strategy",
    "qa_strategy_name",
    default=None,
    help="Entry point name of the QA strategy (overrides priority-based selection).",
)
def consolidate_cmd(
    config_path: str, engagement_id: str, reparse: bool, qa_strategy_name: str | None
) -> None:
    """Re-run normalization and deduplication from persisted raw output.

    Does not re-execute tools. Starts from PARSE (with --reparse) or
    CONSOLIDATE (default). Useful when normalization logic or
    cross-reference mappings change.

    Requires --engagement-id because consolidate operates on an existing
    engagement's persisted raw output.
    """
    path = Path(config_path)

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

        adapters = _helpers.filter_and_validate_adapters(config, adapters)

        start_stage = Stage.PARSE if reparse else Stage.CONSOLIDATE
        console.print(
            f"[bold]Consolidating engagement {engagement_id} "
            f"from stage {start_stage.value}...[/bold]"
        )

        qa_strategy = _helpers.discover_plugin(
            "gxassessms.qa_strategies", name=qa_strategy_name, config=config
        )
        if qa_strategy_name is not None and qa_strategy is None:
            raise click.BadParameter(
                f"QA strategy {qa_strategy_name!r} not found.",
                param_hint="'--qa-strategy'",
            )

        orchestrator.reset_for_rerun(engagement_id, start_stage)
        orchestrator.run_from(
            engagement_id=engagement_id,
            config=config,
            start_stage=start_stage,
            adapters=adapters,
            normalization_policy=_helpers.build_normalization_policy(),
            consolidation_rule=_helpers.build_consolidation_rule(),
            qa_strategy=qa_strategy,
            renderers=[],
            stop_stage=Stage.CONSOLIDATE,
        )

        console.print("\n[bright_green]Consolidation complete.[/bright_green]")

    except GxAssessError as e:
        console.print(f"\n[bright_red]Consolidation failed:[/bright_red] {e}")
        console.print(
            f"[dim]Engagement ID: {engagement_id} -- "
            f"use --engagement-id {engagement_id} to retry.[/dim]"
        )
        logger.error("Consolidation failed: %s", e)
        raise SystemExit(1) from None
