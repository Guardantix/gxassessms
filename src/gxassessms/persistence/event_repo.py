"""EventRepo -- append-only pipeline event journal."""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

from gxassessms.core.config.datetime_utils import format_utc
from gxassessms.core.contracts.errors import PersistenceError
from gxassessms.persistence.database import DatabaseManager
from gxassessms.pipeline.state import PipelineEvent

logger = logging.getLogger(__name__)


class EventRepo:
    """Repository for the append-only pipeline event journal."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    def append(self, event: PipelineEvent) -> None:
        """Append an event to the journal. Events are never updated or deleted."""
        # dict(event.payload) safely converts both MappingProxyType and plain-dict
        # payloads to a serializable dict before encoding.
        payload_json = json.dumps(dict(event.payload))
        timestamp_str = format_utc(event.timestamp)

        try:
            with self._db.connect() as conn:
                conn.execute(
                    "INSERT INTO pipeline_events "
                    "(event_id, engagement_id, timestamp, event_type, actor, payload) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        event.event_id,
                        event.engagement_id,
                        timestamp_str,
                        event.event_type,
                        event.actor,
                        payload_json,
                    ),
                )
        except sqlite3.DatabaseError as exc:
            raise PersistenceError(f"Failed to append event: {exc}") from exc

    def get_events(self, engagement_id: str) -> list[dict[str, Any]]:
        """Get all events for an engagement, ordered by timestamp."""
        try:
            with self._db.connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM pipeline_events "
                    "WHERE engagement_id = ? ORDER BY timestamp, rowid",
                    (engagement_id,),
                ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise PersistenceError(f"Failed to get events: {exc}") from exc
        return [dict(row) for row in rows]

    def get_events_by_type(self, engagement_id: str, event_type: str) -> list[dict[str, Any]]:
        """Get events filtered by type for an engagement."""
        try:
            with self._db.connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM pipeline_events "
                    "WHERE engagement_id = ? AND event_type = ? "
                    "ORDER BY timestamp, rowid",
                    (engagement_id, event_type),
                ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise PersistenceError(f"Failed to get events by type: {exc}") from exc
        return [dict(row) for row in rows]
