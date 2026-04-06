"""mseco engagement -- engagement lifecycle management.

Subcommands:
    mseco engagement create <config.yaml>
    mseco engagement list
    mseco engagement status <id>
    mseco engagement archive <id>
    mseco engagement purge <id> --confirm
    mseco engagement export <id>

All subcommands are thin wrappers around EngagementRepo and ArtifactManager.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, cast

import click
import yaml

import gxassessms.cli._helpers as _helpers
from gxassessms.cli.output import (
    console,
    format_state,
    make_engagement_status_table,
)
from gxassessms.core.config.config import load_config, validate_config
from gxassessms.core.contracts.errors import ConfigError, GxAssessError, PersistenceError

logger = logging.getLogger(__name__)


def _resolve_operator() -> str:
    """Resolve the OS username for audit attribution. Never raises.

    Separate from build_audit_context()["os_user"] so that operator can
    eventually come from an external source (e.g., authenticated identity
    injected by a CI wrapper) rather than the local OS user.
    """
    import getpass

    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _check_storage_permissions(artifacts: Any, engagement_id: str) -> None:
    """Advisory permission check -- never raises, never blocks."""
    from gxassessms.core.security.permissions import warn_broad_permissions

    try:
        eng_dir = artifacts.get_engagement_dir(engagement_id)
        warn_broad_permissions(eng_dir, f"engagement directory for {engagement_id}")
    except GxAssessError:
        logger.debug("advisory permission check skipped for %s", engagement_id)


@click.group("engagement")
def engagement_group() -> None:
    """Manage assessment engagements (create, list, status, archive, restore, purge, export)."""
    pass


@engagement_group.command("create")
@click.argument(
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
)
def create_cmd(config_path: str) -> None:
    """Create a new engagement from a config file.

    Validates the config (required fields and auth method), then creates
    the engagement record, directory structure, and config snapshot.
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
        repo = _helpers.get_engagement_repo()
        engagement_id = repo.create(
            client_name=config.client_name,
            tenant_id=config.tenant_id,
            config_snapshot=config.model_dump(),
        )
        console.print(f"[bright_green]Engagement created:[/bright_green] {engagement_id}")
        console.print(f"Client: {config.client_name}")
        console.print(f"Tenant: {config.tenant_id}")
    except GxAssessError as e:
        console.print(f"[bright_red]Failed to create engagement:[/bright_red] {e}")
        raise SystemExit(1) from None


@engagement_group.command("list")
def list_cmd() -> None:
    """List all engagements."""
    try:
        repo = _helpers.get_engagement_repo()
        engagements = repo.list_all()

        if not engagements:
            console.print("[dim]No engagements found.[/dim]")
            return

        from rich.table import Table

        table = Table(title="Engagements", show_header=True)
        table.add_column("ID", style="bold")
        table.add_column("Client")
        table.add_column("State")
        table.add_column("Created")

        for eng in engagements:
            state_str = format_state(eng.get("state", ""))
            table.add_row(
                eng.get("engagement_id", ""),
                eng.get("client_name", ""),
                state_str,
                eng.get("created_at", ""),
            )

        console.print(table)

    except GxAssessError as e:
        console.print(f"[bright_red]Failed to list engagements:[/bright_red] {e}")
        raise SystemExit(1) from None


@engagement_group.command("status")
@click.argument("engagement_id")
def status_cmd(engagement_id: str) -> None:
    """Show detailed status for an engagement."""
    try:
        repo = _helpers.get_engagement_repo()
        engagement = repo.get(engagement_id)
        if engagement is None:
            console.print(
                f"[bright_red]Error:[/bright_red] Engagement {engagement_id!r} not found."
            )
            raise SystemExit(1)
        table = make_engagement_status_table(engagement)
        console.print(table)
    except GxAssessError as e:
        console.print(f"[bright_red]Failed to get status:[/bright_red] {e}")
        raise SystemExit(1) from None


@engagement_group.command("archive")
@click.argument("engagement_id")
def archive_cmd(engagement_id: str) -> None:
    """Archive an engagement (compress raw output to cold storage).

    Structured data stays in SQLite for analytics. Use 'engagement restore'
    to decompress for re-analysis.
    """
    try:
        repo = _helpers.get_engagement_repo()
        engagement = repo.get(engagement_id)
        if engagement is None:
            console.print(
                f"[bright_red]Error:[/bright_red] Engagement {engagement_id!r} not found."
            )
            raise SystemExit(1)

        artifacts = _helpers.get_artifact_manager()
        _check_storage_permissions(artifacts, engagement_id)
        operator = _resolve_operator()
        artifacts.archive(engagement_id, operator=operator)
        console.print(f"[bright_green]Engagement {engagement_id} archived.[/bright_green]")
        console.print(
            "[dim]Use 'mseco engagement restore <id>' to decompress for re-analysis.[/dim]"
        )
    except GxAssessError as e:
        console.print(f"[bright_red]Archive failed:[/bright_red] {e}")
        raise SystemExit(1) from None


@engagement_group.command("restore")
@click.argument("engagement_id")
def restore_cmd(engagement_id: str) -> None:
    """Restore an archived engagement for re-analysis.

    Decompresses raw output from cold storage back to the active
    engagement directory. The engagement must be in ARCHIVED state.
    """
    try:
        artifacts = _helpers.get_artifact_manager()
        _check_storage_permissions(artifacts, engagement_id)
        operator = _resolve_operator()
        artifacts.restore(engagement_id, operator=operator)
        console.print(f"[bright_green]Engagement {engagement_id} restored.[/bright_green]")
    except GxAssessError as e:
        console.print(f"[bright_red]Restore failed:[/bright_red] {e}")
        raise SystemExit(1) from None


@engagement_group.command("purge")
@click.argument("engagement_id")
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="Required flag to confirm irreversible deletion.",
)
def purge_cmd(engagement_id: str, confirm: bool) -> None:
    """Permanently delete all data for an engagement.

    IRREVERSIBLE. Deletes DB rows (findings, overrides, QA results,
    stage history) and filesystem artifacts (raw output, reports).
    Writes an audit manifest before deletion for GDPR demonstrability.

    Requires --confirm flag.
    """
    if not confirm:
        console.print(
            "[bright_red]Error:[/bright_red] Purge is irreversible. "
            "Pass --confirm to proceed.\n"
            "\n"
            f"  mseco engagement purge {engagement_id} --confirm"
        )
        raise SystemExit(1)

    try:
        artifacts = _helpers.get_artifact_manager()
        _check_storage_permissions(artifacts, engagement_id)
        operator = _resolve_operator()

        manifest: dict[str, Any]
        try:
            eng_dir = artifacts.get_engagement_dir(engagement_id)
        except PersistenceError:
            eng_dir = None

        if eng_dir is not None and eng_dir.exists():
            manifest = artifacts.purge(engagement_id, operator=operator)
        else:
            # Directory missing or already removed -- clean up DB record only
            console.print(
                "[yellow]Note:[/yellow] Engagement directory not found. "
                "Cleaning up database record."
            )
            manifest = {}

        repo = _helpers.get_engagement_repo()
        try:
            repo.delete(engagement_id)
        except GxAssessError as db_err:
            console.print(
                f"[yellow]Warning:[/yellow] Filesystem artifacts deleted but "
                f"DB record removal failed: {db_err}\n"
                f"Re-run 'mseco engagement purge {engagement_id} --confirm' to retry."
            )
            logger.error("Purge DB delete failed for %s: %s", engagement_id, db_err)
            raise SystemExit(1) from None

        console.print(f"[bright_green]Engagement {engagement_id} purged.[/bright_green]")
        if manifest.get("audit_path"):
            console.print(f"Audit manifest: {manifest['audit_path']}")
    except GxAssessError as e:
        console.print(f"[bright_red]Purge failed:[/bright_red] {e}")
        raise SystemExit(1) from None


@engagement_group.command("export")
@click.argument("engagement_id")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["yaml", "json"], case_sensitive=False),
    default="yaml",
    help="Output format for the exported metadata.",
)
def export_cmd(engagement_id: str, output_format: str) -> None:
    """Export engagement metadata (no findings or client data).

    Produces a portable metadata summary for referencing in external
    project management or documentation. Contains engagement ID, client
    name, tenant ID, state, timestamps, and tool list -- no findings.
    """
    try:
        repo = _helpers.get_engagement_repo()
        engagement = repo.get(engagement_id)
        if engagement is None:
            console.print(
                f"[bright_red]Error:[/bright_red] Engagement {engagement_id!r} not found."
            )
            raise SystemExit(1)

        # Extract enabled tool names from config_snapshot (JSON blob).
        # config_snapshot is json.dumps(config.model_dump()) -- always valid JSON
        # with shape: {"tools": {"name": {"enabled": bool, ...}, ...}, ...}
        raw_snap: Any = engagement.get("config_snapshot", "{}")
        parsed: Any = json.loads(raw_snap) if isinstance(raw_snap, str) else raw_snap
        snap = cast(dict[str, Any], parsed) if isinstance(parsed, dict) else {}
        tools_config: dict[str, Any] = snap.get("tools", {}) if snap else {}
        tool_names: list[str] = sorted(
            str(name)
            for name, tc in tools_config.items()
            if isinstance(tc, dict) and cast(dict[str, Any], tc).get("enabled", False)
        )

        metadata: dict[str, Any] = {
            "schema_version": "1.0",
            "engagement_id": engagement.get("engagement_id", ""),
            "client_name": engagement.get("client_name", ""),
            "tenant_id": engagement.get("tenant_id", ""),
            "state": engagement.get("state", ""),
            "created_at": engagement.get("created_at", ""),
            "tools": tool_names,
        }

        if output_format == "json":
            output = json.dumps(metadata, indent=2, default=str)
        else:
            output = yaml.dump(metadata, default_flow_style=False)

        click.echo(output)

        from gxassessms.core.security.audit_context import build_audit_context

        logger.info(
            "Exported engagement metadata: %s",
            json.dumps(
                {"engagement_id": engagement_id, "format": output_format, **build_audit_context()}
            ),
        )

    except GxAssessError as e:
        console.print(f"[bright_red]Export failed:[/bright_red] {e}")
        raise SystemExit(1) from None
