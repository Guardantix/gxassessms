"""CoverageRepo -- control coverage records."""

from __future__ import annotations

import logging
from typing import Any

from gxassessms.core.config.datetime_utils import format_utc, utc_now
from gxassessms.persistence.database import DatabaseManager

logger = logging.getLogger(__name__)


class CoverageRepo:
    """Repository for coverage records."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    def save(
        self,
        engagement_id: str,
        records: list[dict[str, Any]],
    ) -> None:
        """Save a batch of coverage records.

        Each record dict must contain: control_id, tool_source, status.
        Optional: reason.
        """
        now = format_utc(utc_now())
        rows = [
            (
                engagement_id,
                r["control_id"],
                r["tool_source"],
                r["status"],
                r.get("reason"),
                now,
            )
            for r in records
        ]
        with self._db.connect() as conn:
            conn.executemany(
                "INSERT INTO coverage_records "
                "(engagement_id, control_id, tool_source, status, reason, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )
        logger.info(
            "Saved %d coverage records for engagement %s",
            len(records),
            engagement_id,
        )

    def get_for_engagement(self, engagement_id: str) -> list[dict[str, Any]]:
        """Get all coverage records for an engagement."""
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM coverage_records WHERE engagement_id = ? ORDER BY control_id",
                (engagement_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_for_engagement(self, engagement_id: str) -> int:
        """Delete all coverage records for an engagement. Returns count."""
        with self._db.connect() as conn:
            result = conn.execute(
                "DELETE FROM coverage_records WHERE engagement_id = ?",
                (engagement_id,),
            )
        return result.rowcount
