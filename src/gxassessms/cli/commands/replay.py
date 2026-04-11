"""mseco replay -- replay pipeline from persisted raw output.

Usage:
    mseco replay <engagement-id>
    mseco replay <engagement-id> --from parse
    mseco replay <engagement-id> --from consolidate
    mseco replay <engagement-id> --from qa
    mseco replay <engagement-id> --from report

Loads persisted raw output from the engagement directory and re-enters
the pipeline at PARSE or later. Does not re-run tool collection.

When the SQLite DB has been wiped (disaster recovery), replay falls
back to reading `config_snapshot.json` from the engagement directory.

Stage choice mapping:
    parse      -> Stage.PARSE
    consolidate -> Stage.CONSOLIDATE
    qa         -> Stage.QA_REVIEW
    report     -> Stage.RENDER
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

import click
from pydantic import ValidationError

import gxassessms.cli._helpers as _helpers
from gxassessms.cli.output import console
from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.contracts.errors import GxAssessError, PersistenceError
from gxassessms.persistence.artifacts import ArtifactManager
from gxassessms.persistence.engagement_repo import (
    EngagementRepo,
    decode_config_snapshot,
)
from gxassessms.pipeline.state import ENGAGEMENT_ID_PATTERN

logger = logging.getLogger(__name__)

_STAGE_CLI_ALIASES = {"qa": "QA_REVIEW", "report": "RENDER"}


def _load_config_for_replay(
    engagement_id: str,
    repo: EngagementRepo,
    artifact_manager: ArtifactManager,
) -> tuple[EngagementConfig, bool]:
    """Load an engagement's config for replay: DB first, then filesystem.

    Falls back to <eng_dir>/config_snapshot.json when the DB row is missing
    OR the DB itself is corrupt/locked. Raises GxAssessError on invalid
    snapshots; calls SystemExit(1) with a user-facing message when neither
    source is available.

    Returns (config, loaded_from_fallback) so the caller can surface a
    DR-mode indicator on successful replay.
    """
    loaded_from_fallback = False
    snapshot: dict[str, Any]

    # Step 1: DB lookup -- can fail for two distinct reasons:
    #   (a) DB row missing or DB itself unreadable -> fall back to FS
    #   (b) DB row present but bytes are corrupt -> fatal (not fallback-able)
    try:
        engagement = repo.get(engagement_id)
    except (PersistenceError, sqlite3.Error) as e:
        loaded_from_fallback = True
        logger.warning(
            "Engagement %s not loadable from DB (%s); "
            "falling back to filesystem config_snapshot.json",
            engagement_id,
            e,
        )
        console.print(
            f"[yellow]Warning:[/yellow] Engagement {engagement_id!r} not loadable from DB. "
            "Falling back to filesystem config_snapshot.json."
        )
        try:
            snapshot = artifact_manager.read_config_snapshot(engagement_id)
        except PersistenceError as fs_err:
            logger.error(
                "Both DB lookup and filesystem fallback failed for %s: %s",
                engagement_id,
                fs_err,
                exc_info=True,
            )
            console.print(f"[bright_red]Error:[/bright_red] {fs_err}")
            raise SystemExit(1) from None
    else:
        # DB row present -- decode its bytes. Corruption here is fatal
        # (not fallback-able): the operator needs to see "your DB row is
        # broken" rather than silently replaying stale filesystem bytes.
        try:
            snapshot = decode_config_snapshot(engagement)
        except PersistenceError as decode_err:
            raise GxAssessError(
                f"Engagement {engagement_id!r} has a corrupt config snapshot "
                f"in the DB and cannot be replayed: {decode_err}"
            ) from decode_err

    # Step 2: Pydantic validation (same treatment for both source paths).
    try:
        return EngagementConfig.model_validate(snapshot), loaded_from_fallback
    except ValidationError as e:
        # Security: ValidationError.__str__() embeds field values which
        # include tenant_id, client_id, certificate_path. Log only the
        # count + field locations, not values.
        error_locs = [".".join(str(p) for p in err["loc"]) for err in e.errors()]
        raise GxAssessError(
            f"Engagement {engagement_id!r} config_snapshot failed validation "
            f"({e.error_count()} errors at {error_locs})"
        ) from e


def _rehydrate_engagement_if_missing(
    engagement_id: str,
    config: EngagementConfig,
    repo: EngagementRepo,
    engagement_dir: str | None,
) -> bool:
    """Rehydrate the engagement row from a filesystem snapshot (DR path).

    Called only when `_load_config_for_replay` returned
    `loaded_from_fallback=True`. Returns True if a new row was inserted
    and False if the row was already present (detected either via the
    initial `repo.get()` probe or via `rehydrate_from_snapshot`'s own
    duplicate check). Calls SystemExit(1) with a user-facing message
    when the rehydrate INSERT itself fails against a still-broken DB.

    Transient DB errors during the initial probe are tolerated: if
    `repo.get()` raises `sqlite3.Error`, we fall through and let
    `rehydrate_from_snapshot`'s own SELECT+INSERT be the definitive
    check. If the DB has recovered, the INSERT succeeds (or the
    duplicate-ID guard fires, meaning the row was there all along).
    If the DB is still broken, the INSERT raises and we abort then.

    The caller is responsible for gating this path on `start_stage`:
    only PARSE is viable after a DB wipe because CONSOLIDATE/QA/RENDER
    resume paths verify the event journal, which is empty in DR.
    """
    try:
        repo.get(engagement_id)
    except PersistenceError:
        # Expected in the DR case -- fall through and insert the row.
        pass
    except sqlite3.Error as db_err:
        # Transient: let rehydrate_from_snapshot's own SELECT+INSERT
        # be the definitive "is the DB writable / is the row there" test.
        logger.warning(
            "DB lookup failed for %s during DR probe (%s); "
            "deferring decision to rehydrate_from_snapshot",
            engagement_id,
            db_err,
        )
    else:
        # Row exists already -- nothing to rehydrate.
        return False

    try:
        repo.rehydrate_from_snapshot(
            engagement_id=engagement_id,
            client_name=config.client_name,
            tenant_id=config.tenant_id,
            config_snapshot=config.model_dump(mode="json"),
            engagement_dir=engagement_dir,
        )
    except PersistenceError as insert_err:
        # "row already exists" means the DB recovered between the probe
        # and the INSERT and the row was there all along: not an error,
        # just proceed. Other PersistenceErrors (invalid ID, etc.) are
        # fatal.
        if "already exists" in str(insert_err):
            logger.info(
                "Engagement row for %s already present; skipping rehydrate",
                engagement_id,
            )
            return False
        logger.error(
            "Failed to rehydrate engagement %s: %s",
            engagement_id,
            insert_err,
            exc_info=True,
        )
        console.print(
            f"[bright_red]Error:[/bright_red] Failed to rehydrate engagement row "
            f"for {engagement_id!r}: {insert_err}"
        )
        raise SystemExit(1) from None
    except sqlite3.Error as db_err:
        logger.error(
            "DB unreadable during DR rehydrate INSERT for %s: %s",
            engagement_id,
            db_err,
            exc_info=True,
        )
        console.print(
            f"[bright_red]Error:[/bright_red] Database is unreadable; cannot "
            f"rehydrate engagement {engagement_id!r}. Wipe and recreate the DB "
            "per runbook step 2 before retrying `mseco replay`."
        )
        raise SystemExit(1) from None

    console.print(
        f"[yellow]DR:[/yellow] Rehydrated engagement row for {engagement_id!r} "
        "from filesystem config snapshot."
    )
    return True


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
    - Recovering engagement data after a SQLite DB wipe (reads
      `config_snapshot.json` from the engagement directory as a fallback
      when the DB row is missing or unreadable)

    Does NOT re-execute tools (use 'mseco run --rerun' for that).
    """
    # Security: CWE-22 / CWE-117 defense against path traversal and log
    # injection via crafted engagement IDs. Must run before any filesystem
    # or DB access.
    if not ENGAGEMENT_ID_PATTERN.match(engagement_id):
        console.print(
            "[bright_red]Error:[/bright_red] Invalid engagement ID format. "
            "Expected alphanumeric / underscore / hyphen only."
        )
        raise SystemExit(1)

    try:
        from gxassessms.pipeline.stages import Stage

        start_stage = Stage(_STAGE_CLI_ALIASES.get(from_stage, from_stage).upper())

        repo = _helpers.get_engagement_repo()
        artifacts = _helpers.get_artifact_manager()
        config, loaded_from_fallback = _load_config_for_replay(engagement_id, repo, artifacts)

        try:
            engagement_dir = artifacts.get_engagement_dir(engagement_id)
        except PersistenceError:
            console.print(
                f"[bright_red]Error:[/bright_red] No engagement directory found for "
                f"{engagement_id!r}. Has collection been run?"
            )
            raise SystemExit(1) from None

        # DR path: if the config came from the filesystem snapshot, the DB
        # row is almost certainly missing too. Rehydrate it so the
        # downstream `reset_for_rerun` -> `force_update_state` chain has a
        # row to update. Only PARSE is viable after a DB wipe because
        # CONSOLIDATE/QA/RENDER resume paths verify the event journal,
        # which is empty in DR.
        if loaded_from_fallback:
            if start_stage is not Stage.PARSE:
                console.print(
                    f"[bright_red]Error:[/bright_red] Stage {start_stage.value!r} "
                    "cannot be replayed after a DB wipe (event history is gone). "
                    f"Re-run `mseco replay {engagement_id} --from parse` instead."
                )
                raise SystemExit(1) from None
            _rehydrate_engagement_if_missing(engagement_id, config, repo, str(engagement_dir))

        console.print(
            f"[bold]Replaying engagement {engagement_id} from {start_stage.value}...[/bold]"
        )

        qa_strategy = _helpers.discover_plugin(
            _helpers.QA_STRATEGY_GROUP, name=qa_strategy_name, config=config
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

        if loaded_from_fallback:
            console.print(
                "[yellow]Note:[/yellow] Replayed from filesystem config_snapshot "
                "(DB row was missing or unreadable)."
            )
        console.print("\n[bright_green]Replay complete.[/bright_green]")

    except GxAssessError as e:
        console.print(f"\n[bright_red]Replay failed:[/bright_red] {e}")
        logger.error("Replay failed: %s", e)
        raise SystemExit(1) from None
