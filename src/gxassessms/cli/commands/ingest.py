"""``mseco ingest`` -- ingest client-provided raw tool output."""

from __future__ import annotations

import getpass
import json
import logging
from pathlib import Path
from typing import Any

import click
from pydantic import ValidationError as PydanticValidationError

from gxassessms.cli import _helpers
from gxassessms.cli.output import console
from gxassessms.core.contracts.errors import GxAssessError, PersistenceError

logger = logging.getLogger(__name__)


@click.command("ingest")
@click.argument("engagement_id")
@click.option(
    "--tool",
    "tool_slug",
    required=True,
    help="Tool storage slug (e.g., 'scubagear')",
)
@click.option(
    "--from",
    "source_path",
    default=None,
    type=click.Path(exists=True, file_okay=False),
    help="Directory containing raw tool output",
)
@click.option(
    "--replace",
    is_flag=True,
    default=False,
    help="Replace existing raw output for this tool",
)
@click.option(
    "--schema-version",
    "schema_version_override",
    default=None,
    help="Override the default schema version",
)
@click.option(
    "--run-at",
    "run_at_arg",
    default=None,
    help="ISO 8601 timestamp for when the tool was run",
)
@click.option(
    "--operator",
    default=None,
    help="Override the operator identity (default: OS user)",
)
@click.option(
    "--repair-event",
    "repair_event",
    is_flag=True,
    default=False,
    help="Emit missing ingest event from committed manifest (audit-neutral)",
)
def ingest_cmd(
    engagement_id: str,
    tool_slug: str,
    source_path: str | None,
    replace: bool,
    schema_version_override: str | None,
    run_at_arg: str | None,
    operator: str | None,
    repair_event: bool,
) -> None:
    """Ingest client-provided raw tool output into an engagement."""
    # 1. Mutual exclusion: --repair-event is incompatible with --from, --replace,
    #    --schema-version, --run-at
    if repair_event:
        if source_path or replace or schema_version_override or run_at_arg:
            console.print(
                "[bright_red]Error:[/bright_red] --repair-event is mutually exclusive "
                "with --from, --replace, --schema-version, --run-at"
            )
            raise SystemExit(1)
    else:
        if not source_path:
            console.print(
                "[bright_red]Error:[/bright_red] --from is required (unless using --repair-event)"
            )
            raise SystemExit(1)

    # 2. Resolve operator
    try:
        op = operator or getpass.getuser()
    except OSError, KeyError:
        op = "unknown"
    actor = f"human:{op}"

    # 3. Engagement lookup
    try:
        repo = _helpers.get_engagement_repo()
        row = repo.get(engagement_id)
    except GxAssessError as exc:
        console.print(f"[bright_red]Engagement not found:[/bright_red] {exc}")
        raise SystemExit(1) from None

    # 4. Decode config from snapshot
    try:
        from gxassessms.core.config.config import EngagementConfig
        from gxassessms.persistence.engagement_repo import decode_config_snapshot

        snapshot = decode_config_snapshot(row)
        config = EngagementConfig.model_validate(snapshot)
    except (PersistenceError, PydanticValidationError) as exc:
        console.print(f"[bright_red]Config error:[/bright_red] {exc}")
        raise SystemExit(1) from None

    # 5. Resolve adapter
    try:
        adapter = _helpers.resolve_enabled_adapter(tool_slug, config)
        adapter = _helpers.require_ingest_capable(adapter)
    except click.UsageError as exc:
        console.print(f"[bright_red]Error:[/bright_red] {exc}")
        raise SystemExit(1) from None

    # 6. Dispatch to normal or repair-event path
    if repair_event:
        _repair_event(engagement_id, tool_slug, actor)
    else:
        _ingest_normal(
            engagement_id,
            tool_slug,
            adapter,
            source_path,  # type: ignore[arg-type]  # guarded by check above
            replace,
            schema_version_override,
            run_at_arg,
            actor,
        )


def _ingest_normal(
    engagement_id: str,
    tool_slug: str,
    adapter: Any,
    source_path: str,
    replace: bool,
    schema_version_override: str | None,
    run_at_arg: str | None,
    actor: str,
) -> None:
    """Normal ingest path: walk directory, commit artifacts, record event."""
    from gxassessms.core.config.datetime_utils import utc_now
    from gxassessms.core.domain.models import IngestProvenance

    source_dir = Path(source_path)

    # Resolve schema version and timestamp
    schema_version = schema_version_override or adapter.default_schema_version
    if run_at_arg:
        from gxassessms.core.config.datetime_utils import parse_utc

        try:
            timestamp = parse_utc(run_at_arg)
        except ValueError as exc:
            console.print(f"[bright_red]Invalid --run-at:[/bright_red] {exc}")
            raise SystemExit(1) from None
    else:
        timestamp = utc_now()

    # Step 1: Adapter walk -- discover and hash files
    try:
        collection_output = adapter.ingest_from_directory(
            source_dir,
            schema_version=schema_version,
            timestamp=timestamp,
        )
    except GxAssessError as exc:
        console.print(f"[bright_red]Ingest failed:[/bright_red] {exc}")
        raise SystemExit(1) from None

    # Step 2: Build provenance (replaced will be updated by persistence layer)
    provenance = IngestProvenance(
        source_path=str(source_dir.resolve()),
        ingested_at=utc_now(),
        ingested_by=actor,
        replaced=False,  # persistence layer corrects this from actual pre-commit state
    )

    # Step 3: Atomic filesystem commit
    try:
        artifacts = _helpers.get_artifact_manager()
        loaded = artifacts.save_ingested_raw_output(
            engagement_id,
            collection_output,
            ingest_provenance=provenance,
            replace=replace,
        )
    except PersistenceError as exc:
        console.print(f"[bright_red]Persistence error:[/bright_red] {exc}")
        raise SystemExit(1) from None

    # Step 4: Record ingest event (from committed provenance, so replaced is authoritative)
    try:
        orchestrator = _helpers.build_orchestrator()
        orchestrator.record_raw_output_ingested(
            engagement_id=engagement_id,
            actor=actor,
            tool_slug=tool_slug,
            source_path=str(source_dir.resolve()),
            file_count=len(collection_output.artifacts),
            replaced=loaded.raw_output.ingest_provenance.replaced,
        )
    except GxAssessError as exc:
        logger.warning("Failed to record ingest event: %s", exc)
        # Non-fatal: data is committed, event is advisory

    # Success output
    console.print(f"[bright_green]Ingested {tool_slug}[/bright_green] into {engagement_id}")
    console.print(f"  Source: {source_dir.resolve()}")
    console.print(f"  Artifacts: {len(collection_output.artifacts)}")
    if loaded.raw_output.ingest_provenance.replaced:
        console.print("  [yellow]Replaced existing data[/yellow]")


def _repair_event(
    engagement_id: str,
    tool_slug: str,
    actor: str,
) -> None:
    """Audit-neutral repair path -- emit missing event from committed manifest.

    Reads the on-disk manifest for the tool, verifies it was ingested, checks
    for an existing event (idempotency guard), then emits from committed
    provenance.
    """
    try:
        artifacts = _helpers.get_artifact_manager()
        eng_dir = artifacts.get_engagement_dir(engagement_id)
        manifest_path = eng_dir / "raw-output" / "manifests" / f"{tool_slug}.json"

        if not manifest_path.exists():
            console.print(f"[bright_red]No manifest found for {tool_slug}[/bright_red]")
            raise SystemExit(1)

        from gxassessms.core.domain.models import RawToolOutput

        raw = RawToolOutput.model_validate_json(manifest_path.read_text(encoding="utf-8"))

        if raw.source_mode != "ingested":
            console.print(
                f"[bright_red]Manifest for {tool_slug} has "
                f"source_mode={raw.source_mode!r}, not 'ingested' -- "
                f"cannot repair event[/bright_red]"
            )
            raise SystemExit(1)

        # ingest_provenance is guaranteed non-None when source_mode == "ingested"
        # (enforced by RawToolOutput.source_mode_matches_provenance validator)
        prov = raw.ingest_provenance
        assert prov is not None  # noqa: S101 -- model invariant, already validated above

        # Check idempotency -- skip if event already exists
        try:
            orchestrator = _helpers.build_orchestrator()
            event_rows = orchestrator._event_repo.get_events_by_type(
                engagement_id, "raw_output_ingested"
            )
            for row in event_rows:
                try:
                    raw_payload: Any = row["payload"]
                    payload: dict[str, Any] = (
                        json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
                    )
                except json.JSONDecodeError, KeyError:
                    payload = {}
                if payload.get("tool_slug") == tool_slug:
                    console.print(
                        f"[yellow]Event already exists for {tool_slug} -- nothing to do[/yellow]"
                    )
                    return
        except GxAssessError:
            # Can't check; proceed with emission
            orchestrator = _helpers.build_orchestrator()

        # Emit from committed provenance
        orchestrator.record_raw_output_ingested(
            engagement_id=engagement_id,
            actor=actor,
            tool_slug=tool_slug,
            source_path=prov.source_path,
            file_count=len(raw.file_manifest),
            replaced=prov.replaced,
        )
        console.print(f"[bright_green]Repaired ingest event for {tool_slug}[/bright_green]")

    except SystemExit:
        raise
    except GxAssessError as exc:
        console.print(f"[bright_red]Repair failed:[/bright_red] {exc}")
        raise SystemExit(1) from None
