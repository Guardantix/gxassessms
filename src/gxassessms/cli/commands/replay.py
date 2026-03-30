"""mseco replay -- replay pipeline from persisted raw output.

Usage:
    mseco replay <engagement-id>
    mseco replay <engagement-id> --from parse
    mseco replay <engagement-id> --from consolidate
    mseco replay <engagement-id> --from qa
    mseco replay <engagement-id> --from report

Loads persisted raw output from the engagement directory and re-enters
the pipeline at PARSE or later. Does not re-run tool collection.

Stage choice mapping:
    parse      -> Stage.PARSE
    consolidate -> Stage.CONSOLIDATE
    qa         -> Stage.QA_REVIEW
    report     -> Stage.RENDER
"""

from __future__ import annotations

import json
import logging

import click

import gxassessms.cli._helpers as _helpers
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
        from gxassessms.core.config.config import EngagementConfig
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

        # Load config from the engagement's persisted snapshot so RENDER
        # has access to client_name, report_formats, etc.
        repo = _helpers.get_engagement_repo()
        engagement = repo.get(engagement_id)
        snapshot = engagement.get("config_snapshot", "{}")
        try:
            if isinstance(snapshot, str):
                snapshot = json.loads(snapshot)
        except json.JSONDecodeError as e:
            raise GxAssessError(
                f"Engagement {engagement_id!r} has a corrupt config snapshot "
                f"and cannot be replayed: {e}"
            ) from e
        config = EngagementConfig.model_validate(snapshot)

        artifacts = _helpers.get_artifact_manager()
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

        orchestrator = _helpers.build_orchestrator()
        adapters = _helpers.discover_cli_adapters()

        orchestrator.run_from(
            engagement_id=engagement_id,
            config=config,
            start_stage=start_stage,
            adapters=adapters,
            normalization_policy=_helpers.discover_plugin("gxassessms.policies"),
            consolidation_rule=_helpers.discover_plugin("gxassessms.consolidation_rules"),
            qa_strategy=_helpers.discover_plugin("gxassessms.qa_strategies"),
            renderers=_helpers.discover_all_plugins("gxassessms.renderers"),
        )

        console.print("\n[bright_green]Replay complete.[/bright_green]")

    except GxAssessError as e:
        console.print(f"\n[bright_red]Replay failed:[/bright_red] {e}")
        logger.error("Replay failed: %s", e)
        raise SystemExit(1) from None
