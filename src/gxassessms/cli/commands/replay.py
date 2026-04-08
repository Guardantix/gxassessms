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

_STAGE_CLI_ALIASES = {"qa": "QA_REVIEW", "report": "RENDER"}


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
@click.option(
    "--qa-strategy",
    "qa_strategy_name",
    default=None,
    help="Entry point name of the QA strategy (overrides priority-based selection).",
)
def replay_cmd(engagement_id: str, from_stage: str, qa_strategy_name: str | None) -> None:
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
        from gxassessms.pipeline.stages import Stage

        start_stage = Stage(_STAGE_CLI_ALIASES.get(from_stage, from_stage).upper())

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

        qa_strategy = _helpers.discover_plugin(
            "gxassessms.qa_strategies", name=qa_strategy_name, config=config
        )
        if qa_strategy_name is not None and qa_strategy is None:
            raise click.BadParameter(
                f"QA strategy {qa_strategy_name!r} not found.",
                param_hint="'--qa-strategy'",
            )

        orchestrator = _helpers.build_orchestrator()
        adapters = _helpers.discover_cli_adapters()
        adapters = _helpers.filter_and_validate_adapters(config, adapters)

        orchestrator.reset_for_rerun(engagement_id, start_stage)
        orchestrator.run_from(
            engagement_id=engagement_id,
            config=config,
            start_stage=start_stage,
            adapters=adapters,
            normalization_policy=_helpers.build_normalization_policy(),
            consolidation_rule=_helpers.build_consolidation_rule(),
            qa_strategy=qa_strategy,
            renderers=_helpers.discover_all_plugins("gxassessms.renderers"),
        )

        console.print("\n[bright_green]Replay complete.[/bright_green]")

    except GxAssessError as e:
        console.print(f"\n[bright_red]Replay failed:[/bright_red] {e}")
        logger.error("Replay failed: %s", e)
        raise SystemExit(1) from None
