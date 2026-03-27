"""Finding explanation service -- provenance API for consolidated findings.

Stub implementation. Full lineage reconstruction requires pipeline stages
(Plan 3+) to populate the event journal with normalization, consolidation,
and QA events.
"""

from __future__ import annotations

import json
import logging

from gxassessms.core.contracts.errors import PersistenceError
from gxassessms.persistence.database import DatabaseManager
from gxassessms.persistence.types import ExplanationResult

logger = logging.getLogger(__name__)


def _escape_like(value: str) -> str:
    """Escape LIKE wildcard characters for safe use in SQL LIKE clauses."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class FindingExplanationService:
    """Stub provenance API for consolidated findings.

    Reconstructs finding lineage from the event journal. Currently returns
    partial data (overrides only) because pipeline stages that populate
    normalization, consolidation, and QA events are not yet built (Plan 3+).
    """

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    def explain(self, finding_id: str) -> ExplanationResult:
        """Return the lineage of a consolidated finding.

        Keys returned:
        - sources: raw JSON from the sources column (not yet reconstructed
          ToolObservation objects)
        - severity_basis: current severity and override count only; policy
          rule not yet tracked
        - dedup_history: always empty -- consolidation events not populated
          until Plan 3+
        - override_history: all overrides (who/when/why/what)
        - ai_modifications: which QA tasks modified or flagged this finding
        - confidence_basis: raw JSON from confidence column
        """
        with self._db.connect() as conn:
            finding_row = conn.execute(
                "SELECT * FROM consolidated_findings WHERE finding_instance_id = ?",
                (finding_id,),
            ).fetchone()
            if finding_row is None:
                raise PersistenceError(f"Consolidated finding not found: {finding_id}")
            finding = dict(finding_row)

            override_rows = conn.execute(
                "SELECT * FROM overrides WHERE finding_id = ? ORDER BY created_at",
                (finding_id,),
            ).fetchall()
            overrides = [dict(row) for row in override_rows]

            escaped_id = _escape_like(finding_id)
            event_rows = conn.execute(
                "SELECT * FROM pipeline_events "
                "WHERE engagement_id = ? AND payload LIKE ? ESCAPE '\\' "
                "ORDER BY timestamp",
                (finding["engagement_id"], f"%{escaped_id}%"),
            ).fetchall()
            events = [dict(row) for row in event_rows]

        return ExplanationResult(
            finding_instance_id=finding_id,
            sources=json.loads(finding["sources"] or "[]"),
            severity_basis={
                "current_severity": finding["severity"],
                "override_count": len(overrides),
            },
            dedup_history=[],
            override_history=overrides,
            ai_modifications=[e for e in events if e.get("event_type") == "ai_modification"],
            confidence_basis=json.loads(finding["confidence"] or "{}"),
        )
