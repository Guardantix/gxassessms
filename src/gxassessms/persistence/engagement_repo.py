"""EngagementRepo -- lifecycle operations for engagement records."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, cast

from gxassessms.core.config.datetime_utils import format_utc, utc_now
from gxassessms.core.contracts.errors import PersistenceError
from gxassessms.core.domain.enums import EngagementState
from gxassessms.persistence.database import DatabaseManager

logger = logging.getLogger(__name__)


_CONFIG_SNAPSHOT_MAX_BYTES = 1_048_576  # 1 MB -- DoS ceiling for parse


def decode_config_snapshot(engagement_row: dict[str, Any]) -> dict[str, Any]:
    """Decode the `config_snapshot` column of an engagement row to a dict.

    The column is stored as a JSON string by `EngagementRepo.create()`,
    but some DB adapters may pre-hydrate it to a dict. Accepts either;
    rejects anything else.

    Raises PersistenceError if the column is absent, null, corrupt JSON,
    or not a JSON object. A missing key and a null value are reported
    distinctly: the former implies a schema/query regression, while the
    latter implies the column was written null.
    """
    if "config_snapshot" not in engagement_row:
        raise PersistenceError("engagement row is missing config_snapshot column")
    raw = engagement_row["config_snapshot"]
    if raw is None:
        raise PersistenceError("engagement row has null config_snapshot")
    if isinstance(raw, dict):
        return cast(dict[str, Any], raw)
    if not isinstance(raw, str):
        raise PersistenceError(
            f"engagement row config_snapshot is {type(raw).__name__}, expected str or dict"
        )
    if raw == "":
        raise PersistenceError("engagement row has empty config_snapshot")
    # DoS ceiling: SQLite TEXT column can hold up to 1 GB, but a sane
    # config_snapshot is a few KB. Refuse to parse pathologically large
    # values (hand-edited or adversarial rows).
    if len(raw) > _CONFIG_SNAPSHOT_MAX_BYTES:
        raise PersistenceError(
            f"engagement row config_snapshot is suspiciously large "
            f"({len(raw)} bytes, ceiling is {_CONFIG_SNAPSHOT_MAX_BYTES}); "
            "refusing to parse"
        )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PersistenceError(f"engagement row config_snapshot is corrupt JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise PersistenceError(
            f"engagement row config_snapshot decoded to {type(parsed).__name__}, expected object"
        )
    return cast(dict[str, Any], parsed)


class EngagementRepo:
    """Repository for engagement lifecycle operations."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    def create(
        self,
        client_name: str,
        tenant_id: str,
        config_snapshot: dict[str, Any],
        engagement_dir: str | None = None,
    ) -> str:
        """Create a new engagement. Returns the engagement_id."""
        engagement_id = str(uuid.uuid4())
        now = format_utc(utc_now())
        config_json = json.dumps(config_snapshot)

        with self._db.connect() as conn:
            conn.execute(
                "INSERT INTO engagements "
                "(engagement_id, client_name, tenant_id, state, created_at, "
                "config_snapshot, engagement_dir) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    engagement_id,
                    client_name,
                    tenant_id,
                    EngagementState.CREATED.value,
                    now,
                    config_json,
                    engagement_dir,
                ),
            )
        logger.info("Created engagement %s for client %s", engagement_id, client_name)
        return engagement_id

    def get(self, engagement_id: str) -> dict[str, Any]:
        """Get an engagement by ID. Raises PersistenceError if not found."""
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM engagements WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchone()
        if row is None:
            raise PersistenceError(f"Engagement not found: {engagement_id}")
        return dict(row)

    def update_state(self, engagement_id: str, state: EngagementState) -> None:
        """Update the state of an engagement."""
        now = format_utc(utc_now())
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT state FROM engagements WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchone()
            if row is None:
                raise PersistenceError(f"Engagement not found: {engagement_id}")

            try:
                current_state = EngagementState(row["state"])
            except ValueError as e:
                raise PersistenceError(
                    f"Unrecognized engagement state {row['state']!r} for {engagement_id}"
                ) from e

            EngagementState.assert_can_transition_to(current_state, state)

            conn.execute(
                "UPDATE engagements SET state = ?, updated_at = ? WHERE engagement_id = ?",
                (state.value, now, engagement_id),
            )
        logger.info("Updated engagement %s state to %s", engagement_id, state.value)

    def force_update_state(self, engagement_id: str, state: EngagementState) -> None:
        """Update engagement state without transition validation.

        Used exclusively for crash recovery where backward transitions
        (e.g. COLLECTING -> CREATED) are required. Normal code paths
        should use update_state() which enforces the state machine.
        """
        now = format_utc(utc_now())
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM engagements WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchone()
            if row is None:
                raise PersistenceError(f"Engagement not found: {engagement_id}")

            conn.execute(
                "UPDATE engagements SET state = ?, updated_at = ? WHERE engagement_id = ?",
                (state.value, now, engagement_id),
            )
        logger.info(
            "Force-updated engagement %s state to %s (bypass validation)",
            engagement_id,
            state.value,
        )

    def list_by_client(self, client_name: str) -> list[dict[str, Any]]:
        """List all engagements for a client."""
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM engagements WHERE client_name = ? ORDER BY created_at DESC",
                (client_name,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_all(self) -> list[dict[str, Any]]:
        """List all engagements, most recent first."""
        with self._db.connect() as conn:
            rows = conn.execute("SELECT * FROM engagements ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]

    def delete(self, engagement_id: str) -> None:
        """Delete an engagement and all related records.

        Deletes explicitly from all child tables in dependency order.
        Schema defines no ON DELETE CASCADE -- explicit deletion in
        dependency order is required.
        """
        # Pre-check existence before attempting deletion
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM engagements WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchone()
            if row is None:
                raise PersistenceError(f"Engagement not found: {engagement_id}")

            for table in [
                "pipeline_events",
                "overrides",
                "stage_history",
                "longitudinal_snapshots",
                "coverage_records",
                "tool_run_results",
                "consolidated_findings",
                "findings",
                "engagements",
            ]:
                conn.execute(
                    f"DELETE FROM {table} WHERE engagement_id = ?",  # noqa: S608
                    (engagement_id,),
                )
        logger.info("Deleted all data for engagement %s", engagement_id)
