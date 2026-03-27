"""EngagementRepo -- lifecycle operations for engagement records."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from gxassessms.core.config.datetime_utils import format_utc, utc_now
from gxassessms.core.contracts.errors import PersistenceError
from gxassessms.core.domain.enums import EngagementState
from gxassessms.persistence.database import DatabaseManager

logger = logging.getLogger(__name__)


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
