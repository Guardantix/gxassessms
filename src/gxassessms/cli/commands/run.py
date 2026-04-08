"""mseco run -- execute the full assessment pipeline.

Usage:
    mseco run <config.yaml>
    mseco run --dry-run <config.yaml>
    mseco run --force-stage PARSE <config.yaml>
    mseco run --rerun <config.yaml>

Thin wrapper: loads config, discovers adapters, builds orchestrator, runs.
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


@click.command("run")
@click.argument(
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
)
@click.option(
    "--engagement-id",
    default=None,
    help="Resume or re-run an existing engagement instead of creating a new one.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Validate config and report execution plan without running tools.",
)
@click.option(
    "--force-stage",
    type=click.Choice(
        ["COLLECT", "PARSE", "CONSOLIDATE", "QA_REVIEW", "RENDER"],
        case_sensitive=False,
    ),
    default=None,
    help="Invalidate a specific stage and re-run from there (requires --engagement-id).",
)
@click.option(
    "--rerun",
    is_flag=True,
    default=False,
    help="Fully re-run all stages regardless of hash state (requires --engagement-id).",
)
@click.option(
    "--qa-strategy",
    "qa_strategy_name",
    default=None,
    help="Entry point name of the QA strategy (overrides priority-based selection).",
)
def run_cmd(
    config_path: str,
    engagement_id: str | None,
    dry_run: bool,
    force_stage: str | None,
    rerun: bool,
    qa_strategy_name: str | None,
) -> None:
    """Run the full assessment pipeline.

    Loads the engagement config, discovers adapters, and executes all
    pipeline stages from COLLECT through RENDER.

    Creates a new engagement by default. Pass --engagement-id to resume
    or re-run an existing engagement (use with --force-stage or --rerun
    to override stage hash checks).

    Re-running on a COMPLETE engagement is a no-op unless --force-stage
    or --rerun is provided.
    """
    if force_stage and engagement_id is None:
        console.print(
            "[bright_red]Error:[/bright_red] --force-stage requires --engagement-id. "
            "Specify an existing engagement to force-restart a stage."
        )
        raise SystemExit(1)

    if rerun and engagement_id is None:
        console.print(
            "[bright_red]Error:[/bright_red] --rerun requires --engagement-id. "
            "Specify an existing engagement to re-run."
        )
        raise SystemExit(1)

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

    if dry_run:
        console.print("[bold]Dry run mode[/bold] -- reporting execution plan only.\n")
        adapters = _helpers.discover_cli_adapters()
        enabled = [name for name, tc in config.tools.items() if tc.enabled]
        console.print(f"Client: {config.client_name}")
        console.print(f"Tenant: {config.tenant_id}")
        console.print(f"Enabled tools: {', '.join(enabled) if enabled else 'none'}")
        console.print(f"Discovered adapters: {len(adapters)}")
        console.print(f"Report formats: {', '.join(config.report_formats)}")
        console.print(
            "\n[green]Config valid.[/green] "
            "Run 'mseco preflight' for full prerequisite and auth validation."
        )
        return

    try:
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

        adapters = _helpers.filter_and_validate_adapters(config, adapters)

        if not adapters:
            console.print(
                "[bright_red]Error:[/bright_red] No adapters discovered -- "
                "install at least one adapter package (e.g., gxassessms-scubagear)."
            )
            created_note = " (just created)" if newly_created else ""
            console.print(
                f"[dim]Engagement {engagement_id}{created_note} -- "
                f"use --engagement-id {engagement_id} to retry after installing adapters.[/dim]"
            )
            raise SystemExit(1)

        from gxassessms.pipeline.stages import Stage
        from gxassessms.pipeline.state import EngagementState

        run_kwargs = {
            "config": config,
            "adapters": adapters,
            "normalization_policy": _helpers.build_normalization_policy(),
            "consolidation_rule": _helpers.build_consolidation_rule(),
            "qa_strategy": _helpers.discover_plugin(
                "gxassessms.qa_strategies", name=qa_strategy_name, config=config
            ),
            "renderers": _helpers.discover_all_plugins("gxassessms.renderers"),
        }

        if qa_strategy_name is not None and run_kwargs["qa_strategy"] is None:
            raise click.BadParameter(
                f"QA strategy {qa_strategy_name!r} not found.",
                param_hint="'--qa-strategy'",
            )

        if rerun:
            console.print("[bold]Re-running all stages...[/bold]")
            orchestrator.reset_for_rerun(engagement_id, Stage.COLLECT)
            orchestrator.run(engagement_id=engagement_id, **run_kwargs)
        elif force_stage:
            stage = Stage(force_stage.upper())
            console.print(f"[bold]Forcing re-run from stage {stage.value}...[/bold]")
            orchestrator.reset_for_rerun(engagement_id, stage)
            orchestrator.run_from(engagement_id=engagement_id, start_stage=stage, **run_kwargs)
        else:
            resume_stage = orchestrator.determine_resume_stage(engagement_id)
            if resume_stage is None:
                current_state = orchestrator._get_current_state(engagement_id)
                if current_state == EngagementState.COMPLETE:
                    console.print(
                        "[green]Engagement is already COMPLETE.[/green] "
                        "Use --force-stage to re-run a specific stage, "
                        "or --rerun to re-run all stages."
                    )
                elif current_state == EngagementState.QA_REVIEW:
                    console.print(
                        "[yellow]Engagement is awaiting QA approval.[/yellow] "
                        "Approve via the review UI before running to completion."
                    )
                return

            orchestrator.reset_for_rerun(engagement_id, resume_stage)
            console.print(f"[bold]Resuming from stage {resume_stage.value}...[/bold]")
            orchestrator.run_from(
                engagement_id=engagement_id, start_stage=resume_stage, **run_kwargs
            )

        console.print("\n[bright_green]Pipeline complete.[/bright_green]")
        console.print(f"[dim]Engagement ID: {engagement_id}[/dim]")

    except GxAssessError as e:
        console.print(f"\n[bright_red]Pipeline failed:[/bright_red] {e}")
        if engagement_id:
            console.print(
                f"[dim]Engagement ID: {engagement_id} -- "
                f"use --engagement-id {engagement_id} to retry or resume.[/dim]"
            )
        logger.error("Pipeline failed: %s", e)
        raise SystemExit(1) from None
