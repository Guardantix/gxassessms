"""``mseco ingest`` -- ingest client-provided raw tool output."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import click
from pydantic import ValidationError as PydanticValidationError

from gxassessms.cli import _helpers
from gxassessms.cli.output import console
from gxassessms.core.contracts.errors import GxAssessError, LockTimeoutError, PersistenceError
from gxassessms.core.domain.constants import SOURCE_MODE_INGESTED
from gxassessms.persistence.artifacts import RAW_OUTPUT_DIR

logger = logging.getLogger(__name__)

_SCHEMA_VERSION_RE = re.compile(r"\d+\.\d+\.\d+|\d{4}-\d{2}-\d{2}")


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

    if repair_event:
        _repair_event(engagement_id, tool_slug)
        return

    actor = f"human:{_helpers.resolve_operator(operator)}"

    try:
        repo = _helpers.get_engagement_repo()
        row = repo.get(engagement_id)
    except GxAssessError as exc:
        console.print(f"[bright_red]Engagement not found:[/bright_red] {exc}")
        raise SystemExit(1) from None

    try:
        from gxassessms.core.config.config import EngagementConfig
        from gxassessms.persistence.engagement_repo import decode_config_snapshot

        snapshot = decode_config_snapshot(row)
        config = EngagementConfig.model_validate(snapshot)
    except (PersistenceError, PydanticValidationError) as exc:
        console.print(f"[bright_red]Config error:[/bright_red] {exc}")
        raise SystemExit(1) from None

    try:
        adapter = _helpers.resolve_enabled_adapter(tool_slug, config)
        adapter = _helpers.require_ingest_capable(adapter)
    except click.UsageError as exc:
        console.print(f"[bright_red]Error:[/bright_red] {exc}")
        raise SystemExit(1) from None

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
    """Normal ingest path: resolve timestamp, invoke adapter, persist artifacts, record event."""
    from gxassessms.core.config.datetime_utils import utc_now
    from gxassessms.core.domain.models import IngestProvenance

    source_dir = Path(source_path)
    resolved_source = source_dir.resolve()

    schema_version = schema_version_override or adapter.default_schema_version
    if not _SCHEMA_VERSION_RE.fullmatch(schema_version):
        if schema_version_override:
            console.print(
                f"[bright_red]Invalid --schema-version:[/bright_red] "
                f"{schema_version!r} is not a valid version string (X.Y.Z or YYYY-MM-DD)"
            )
        else:
            console.print(
                f"[bright_red]Error:[/bright_red] Adapter default_schema_version "
                f"{schema_version!r} is not a valid version string -- this is an adapter bug"
            )
        raise SystemExit(1)
    if run_at_arg:
        from gxassessms.core.config.datetime_utils import parse_utc

        try:
            timestamp = parse_utc(run_at_arg)
        except ValueError as exc:
            console.print(f"[bright_red]Invalid --run-at:[/bright_red] {exc}")
            raise SystemExit(1) from None
    else:
        timestamp = utc_now()

    try:
        collection_output = adapter.ingest_from_directory(
            source_dir,
            schema_version=schema_version,
            timestamp=timestamp,
        )
    except (GxAssessError, ValueError, OSError) as exc:
        console.print(f"[bright_red]Ingest failed:[/bright_red] {exc}")
        raise SystemExit(1) from None

    provenance = IngestProvenance(
        source_path=str(resolved_source),
        ingested_at=utc_now(),
        ingested_by=actor,
        replaced=False,  # persistence layer corrects this from actual pre-commit state
    )

    lock = _helpers.get_engagement_lock()
    try:
        with lock.hold(engagement_id):
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

            try:
                orchestrator = _helpers.build_orchestrator()
                orchestrator.record_raw_output_ingested(
                    engagement_id=engagement_id,
                    actor=actor,
                    tool_slug=tool_slug,
                    source_path=str(resolved_source),
                    file_count=len(collection_output.artifacts),
                    replaced=loaded.raw_output.ingest_provenance.replaced,
                )
            except GxAssessError as exc:
                logger.warning("Failed to record ingest event: %s", exc, exc_info=True)
                # Non-fatal: data is committed, event is advisory
                console.print(
                    f"[yellow]Warning:[/yellow] Data committed but event recording failed. "
                    f"Run [bold]mseco ingest {engagement_id} --tool {tool_slug}"
                    f" --repair-event[/bold] to fix the audit trail."
                )
    except LockTimeoutError as exc:
        console.print(f"[bright_red]Engagement locked:[/bright_red] {exc}")
        raise SystemExit(1) from None

    console.print(f"[bright_green]Ingested {tool_slug}[/bright_green] into {engagement_id}")
    console.print(f"  Source: {resolved_source}")
    console.print(f"  Artifacts: {len(collection_output.artifacts)}")
    if loaded.raw_output.ingest_provenance.replaced:
        console.print("  [yellow]Replaced existing data[/yellow]")


def _repair_event(
    engagement_id: str,
    tool_slug: str,
) -> None:
    """Audit-neutral repair path -- emit missing event from committed manifest.

    Reads the on-disk manifest for the tool, verifies it was ingested, checks
    for an existing event (idempotency guard), then emits from committed
    provenance.
    """
    from gxassessms.core.domain.constants import TOOL_SLUG_PATTERN

    if not re.fullmatch(TOOL_SLUG_PATTERN, tool_slug):
        console.print(f"[bright_red]Invalid tool slug:[/bright_red] {tool_slug!r}")
        raise SystemExit(1)

    try:
        artifacts = _helpers.get_artifact_manager()
        eng_dir = artifacts.get_engagement_dir(engagement_id)
        manifest_path = eng_dir / RAW_OUTPUT_DIR / "manifests" / f"{tool_slug}.json"

        if not manifest_path.exists():
            console.print(f"[bright_red]No manifest found for {tool_slug}[/bright_red]")
            raise SystemExit(1)

        from gxassessms.core.domain.models import RawToolOutput

        raw = RawToolOutput.model_validate_json(manifest_path.read_text(encoding="utf-8"))

        if raw.source_mode != SOURCE_MODE_INGESTED:
            console.print(
                f"[bright_red]Manifest for {tool_slug} has "
                f"source_mode={raw.source_mode!r}, not {SOURCE_MODE_INGESTED!r} -- "
                f"cannot repair event[/bright_red]"
            )
            raise SystemExit(1)

        # ingest_provenance is guaranteed non-None when source_mode == "ingested"
        # (enforced by RawToolOutput.source_mode_matches_provenance validator)
        prov = raw.ingest_provenance
        assert prov is not None  # noqa: S101 -- model invariant, already validated above

        lock = _helpers.get_engagement_lock()
        with lock.hold(engagement_id):
            orchestrator = _helpers.build_orchestrator()
            try:
                if orchestrator.has_raw_output_ingested_event(
                    engagement_id, tool_slug, source_path=prov.source_path
                ):
                    console.print(
                        f"[yellow]Event already exists for {tool_slug} -- nothing to do[/yellow]"
                    )
                    return
            except GxAssessError as exc:
                logger.warning(
                    "Could not check for existing event for %s/%s: %s",
                    engagement_id,
                    tool_slug,
                    exc,
                    exc_info=True,
                )
                console.print(
                    f"[yellow]Warning:[/yellow] Could not check for existing event "
                    f"({exc}); a duplicate may be emitted."
                )

            orchestrator.record_raw_output_ingested(
                engagement_id=engagement_id,
                actor=prov.ingested_by,  # from committed manifest, not current CLI invocation
                tool_slug=tool_slug,
                source_path=prov.source_path,
                file_count=len(raw.file_manifest),
                replaced=prov.replaced,
            )
        console.print(f"[bright_green]Repaired ingest event for {tool_slug}[/bright_green]")

    except LockTimeoutError as exc:
        console.print(f"[bright_red]Engagement locked:[/bright_red] {exc}")
        raise SystemExit(1) from None
    except SystemExit:
        raise
    except (
        GxAssessError,
        OSError,
        PydanticValidationError,
        UnicodeDecodeError,
    ) as exc:  # UnicodeDecodeError: binary/corrupted manifest from read_text()
        console.print(f"[bright_red]Repair failed:[/bright_red] {exc}")
        raise SystemExit(1) from None
