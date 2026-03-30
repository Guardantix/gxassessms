"""mseco report -- generate deliverables only.

Usage:
    mseco report <config.yaml>

Runs the RENDER stage only, producing reports from existing consolidated
findings. The engagement must have completed consolidation first.
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


@click.command("report")
@click.argument(
    "config_path",
    type=click.Path(exists=False),
)
@click.option(
    "--engagement-id",
    required=True,
    help="ID of the engagement to render (required -- report operates on existing findings).",
)
def report_cmd(config_path: str, engagement_id: str) -> None:
    """Generate report deliverables from existing consolidated findings.

    Runs the RENDER stage only. The engagement must already be in
    QA_APPROVED state (consolidation and QA review must be complete).

    Requires --engagement-id because report operates on an existing
    engagement's consolidated findings.
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

        console.print(f"[bold]Generating reports for engagement {engagement_id}...[/bold]")

        orchestrator.run_from(
            engagement_id=engagement_id,
            config=config,
            start_stage=Stage.RENDER,
            adapters=[],
            normalization_policy=None,
            consolidation_rule=None,
            qa_strategy=None,
            renderers=_helpers.discover_all_plugins("gxassessms.renderers"),
        )

        console.print("\n[bright_green]Report generation complete.[/bright_green]")

    except GxAssessError as e:
        console.print(f"\n[bright_red]Report generation failed:[/bright_red] {e}")
        logger.error("Report generation failed: %s", e)
        raise SystemExit(1) from None
