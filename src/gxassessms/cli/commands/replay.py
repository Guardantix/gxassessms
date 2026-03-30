"""mseco replay -- replay pipeline from persisted raw output.

Usage:
    mseco replay <engagement-id>
    mseco replay <engagement-id> --from parse
    mseco replay <engagement-id> --from consolidate

Loads persisted raw output from the engagement directory and re-enters
the pipeline at PARSE or later. Does not re-run tool collection.
"""

from __future__ import annotations

import logging

import click

from gxassessms.cli._helpers import (
    build_orchestrator,
    discover_all_plugins,
    discover_cli_adapters,
    discover_plugin,
    get_artifact_manager,
)
from gxassessms.cli.output import console
from gxassessms.core.contracts.errors import GxAssessError

logger = logging.getLogger(__name__)


@click.command("replay")
@click.argument("engagement_id")
@click.option(
    "--from",
    "from_stage",
    type=click.Choice(
        ["parse", "consolidate", "qa", "report"],
        case_sensitive=False,
    ),
    default="parse",
    help="Pipeline stage to replay from (default: parse).",
)
def replay_cmd(engagement_id: str, from_stage: str) -> None:
    """Replay the pipeline from persisted raw output.

    Loads raw tool output saved during a previous collection and
    re-runs the pipeline from the specified stage. Useful for:

    - Debugging consolidation logic against real data without re-running tools
    - Re-running normalization after updating severity/category mappings
    - Iterating on report generation

    Does NOT re-execute tools (use 'mseco run --rerun' for that).
    """
    try:
        from gxassessms.pipeline.replay import ReplayEngine
        from gxassessms.pipeline.stages import Stage

        stage_map = {
            "parse": Stage.PARSE,
            "consolidate": Stage.CONSOLIDATE,
            "qa": Stage.QA_REVIEW,
            "report": Stage.RENDER,
        }
        start_stage = stage_map[from_stage.lower()]

        replay_engine = ReplayEngine()
        replay_engine.validate_start_stage(start_stage)

        artifacts = get_artifact_manager()
        eng_dir = artifacts.get_engagement_dir(engagement_id)
        if not eng_dir.exists():
            console.print(
                f"[bright_red]Error:[/bright_red] No raw output found for "
                f"engagement {engagement_id!r}. Has collection been run?"
            )
            raise SystemExit(1)

        console.print(
            f"[bold]Replaying engagement {engagement_id} from {start_stage.value}...[/bold]"
        )

        orchestrator = build_orchestrator()
        adapters = discover_cli_adapters()

        orchestrator.run_from(
            engagement_id=engagement_id,
            config=None,
            start_stage=start_stage,
            adapters=adapters,
            normalization_policy=discover_plugin("gxassessms.policies"),
            consolidation_rule=discover_plugin("gxassessms.consolidation_rules"),
            qa_strategy=discover_plugin("gxassessms.qa_strategies"),
            renderers=discover_all_plugins("gxassessms.renderers"),
        )

        console.print("\n[bright_green]Replay complete.[/bright_green]")

    except GxAssessError as e:
        console.print(f"\n[bright_red]Replay failed:[/bright_red] {e}")
        logger.error("Replay failed: %s", e)
        raise SystemExit(1) from None
