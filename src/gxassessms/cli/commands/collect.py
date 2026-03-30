"""mseco collect -- run assessment tools only (no parsing or reporting).

Usage:
    mseco collect <config.yaml>

Thin wrapper: loads config, discovers adapters, runs COLLECT stage only.
Useful for collecting raw tool output before iterating on normalization.
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


@click.command("collect")
@click.argument(
    "config_path",
    type=click.Path(exists=False),
)
@click.option(
    "--engagement-id",
    default=None,
    help="Target an existing engagement instead of creating a new one.",
)
def collect_cmd(config_path: str, engagement_id: str | None) -> None:
    """Run assessment tools only (no parsing, consolidation, or reporting).

    Executes the COLLECT stage: runs all enabled tools in parallel,
    persists raw output to the engagement directory. Use 'mseco consolidate'
    or 'mseco run' to process the collected data.

    Creates a new engagement by default; pass --engagement-id to target
    an existing one (e.g., after a partial or failed collection).
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

        newly_created = engagement_id is None
        if engagement_id is None:
            repo = _helpers.get_engagement_repo()
            engagement_id = repo.create(
                client_name=config.client_name,
                tenant_id=config.tenant_id,
                config_snapshot=config.model_dump(),
            )
            console.print(f"[cyan]Engagement created:[/cyan] {engagement_id}")
        else:
            console.print(f"[cyan]Using engagement:[/cyan] {engagement_id}")

        orchestrator = _helpers.build_orchestrator()
        adapters = _helpers.discover_cli_adapters()

        if not adapters:
            console.print(
                "[bright_red]Error:[/bright_red] No adapters discovered -- "
                "install at least one adapter package (e.g., gxassessms-scubagear)."
            )
            if newly_created:
                console.print(
                    f"[dim]Engagement {engagement_id} was created. "
                    f"Use --engagement-id {engagement_id} to retry after installing adapters.[/dim]"
                )
            else:
                console.print(
                    f"[dim]Engagement ID: {engagement_id} -- "
                    f"use --engagement-id {engagement_id} to retry after installing adapters.[/dim]"
                )
            raise SystemExit(1)

        console.print(f"[bold]Collecting from {len(adapters)} adapter(s)...[/bold]")

        orchestrator.run_from(
            engagement_id=engagement_id,
            config=config,
            start_stage=Stage.COLLECT,
            adapters=adapters,
            normalization_policy=None,
            consolidation_rule=None,
            qa_strategy=None,
            renderers=[],
            stop_stage=Stage.COLLECT,
        )

        console.print("\n[bright_green]Collection complete.[/bright_green]")
        console.print(f"[dim]Engagement ID: {engagement_id}[/dim]")

    except GxAssessError as e:
        console.print(f"\n[bright_red]Collection failed:[/bright_red] {e}")
        if engagement_id:
            console.print(
                f"[dim]Engagement ID: {engagement_id} -- "
                f"use --engagement-id {engagement_id} to retry.[/dim]"
            )
        logger.error("Collection failed: %s", e)
        raise SystemExit(1) from None
