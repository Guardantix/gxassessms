"""Repository classes -- pipeline and UI never write SQL directly.

All database access goes through these repositories. Each repository
takes a DatabaseManager and operates through its connect() context manager.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from gxassessms.core.config.datetime_utils import format_utc, utc_now
from gxassessms.core.contracts.errors import InvalidTransitionError, PersistenceError
from gxassessms.core.domain.enums import FindingStatus, Severity
from gxassessms.persistence.database import DatabaseManager
from gxassessms.pipeline.state import EngagementState, PipelineEvent

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
            # Fetch current state for transition validation
            row = conn.execute(
                "SELECT state FROM engagements WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchone()
            if row is None:
                raise PersistenceError(f"Engagement not found: {engagement_id}")

            current_state = EngagementState(row["state"])
            if not EngagementState.can_transition_to(current_state, state):
                raise InvalidTransitionError(
                    message=f"Cannot transition from {current_state.value} to {state.value}",
                    from_state=current_state.value,
                    to_state=state.value,
                )

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
        """
        with self._db.connect() as conn:
            # Delete in dependency order (child tables first)
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


class EventRepo:
    """Repository for the append-only pipeline event journal."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    def append(self, event: PipelineEvent) -> None:
        """Append an event to the journal. Events are never updated or deleted."""
        payload_json = json.dumps(event.payload)
        timestamp_str = format_utc(event.timestamp)

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

    def get_events(self, engagement_id: str) -> list[dict[str, Any]]:
        """Get all events for an engagement, ordered by timestamp."""
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM pipeline_events WHERE engagement_id = ? ORDER BY timestamp, rowid",
                (engagement_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_events_by_type(self, engagement_id: str, event_type: str) -> list[dict[str, Any]]:
        """Get events filtered by type for an engagement."""
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM pipeline_events "
                "WHERE engagement_id = ? AND event_type = ? "
                "ORDER BY timestamp, rowid",
                (engagement_id, event_type),
            ).fetchall()
        return [dict(row) for row in rows]


class FindingRepo:
    """Repository for parsed and consolidated findings."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    def save_parsed(
        self,
        engagement_id: str,
        findings: list[dict[str, Any]],
    ) -> None:
        """Save a batch of parsed findings.

        Each finding dict must contain: finding_id, observation_id, finding_key,
        tool_source, title, severity, status, category, description, dedup_keys.
        Optional: benchmark_refs, raw_data.
        """
        now = format_utc(utc_now())
        with self._db.connect() as conn:
            for f in findings:
                conn.execute(
                    "INSERT INTO findings "
                    "(finding_id, engagement_id, observation_id, finding_key, "
                    "tool_source, title, severity, status, category, description, "
                    "dedup_keys, benchmark_refs, raw_data, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        f["finding_id"],
                        engagement_id,
                        f["observation_id"],
                        f["finding_key"],
                        f["tool_source"],
                        f["title"],
                        f["severity"],
                        f["status"],
                        f["category"],
                        f["description"],
                        json.dumps(f.get("dedup_keys", [])),
                        json.dumps(f.get("benchmark_refs", [])),
                        json.dumps(f.get("raw_data", {})),
                        now,
                    ),
                )
        logger.info(
            "Saved %d parsed findings for engagement %s",
            len(findings),
            engagement_id,
        )

    def save_consolidated(
        self,
        engagement_id: str,
        findings: list[dict[str, Any]],
    ) -> None:
        """Save a batch of consolidated findings.

        Each finding dict must contain: finding_instance_id, finding_key,
        title, severity, status, category, description, sources, confidence.
        Optional: benchmark_refs, root_cause, remediation, narrative.
        """
        now = format_utc(utc_now())
        with self._db.connect() as conn:
            for f in findings:
                conn.execute(
                    "INSERT INTO consolidated_findings "
                    "(finding_instance_id, engagement_id, finding_key, title, "
                    "severity, status, category, description, sources, "
                    "confidence, benchmark_refs, root_cause, remediation, "
                    "narrative, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        f["finding_instance_id"],
                        engagement_id,
                        f["finding_key"],
                        f["title"],
                        f["severity"],
                        f["status"],
                        f["category"],
                        f["description"],
                        json.dumps(f["sources"]),
                        json.dumps(f["confidence"]),
                        json.dumps(f.get("benchmark_refs", [])),
                        f.get("root_cause"),
                        f.get("remediation"),
                        f.get("narrative"),
                        now,
                    ),
                )
        logger.info(
            "Saved %d consolidated findings for engagement %s",
            len(findings),
            engagement_id,
        )

    def get_consolidated(self, engagement_id: str) -> list[dict[str, Any]]:
        """Get all consolidated findings for an engagement."""
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM consolidated_findings "
                "WHERE engagement_id = ? ORDER BY severity, title",
                (engagement_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_parsed(self, engagement_id: str) -> list[dict[str, Any]]:
        """Get all parsed findings for an engagement."""
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE engagement_id = ? ORDER BY severity, title",
                (engagement_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def override_severity(
        self,
        finding_id: str,
        new_severity: Severity,
        reason: str,
        actor: str,
        engagement_id: str,
    ) -> None:
        """Override the severity of a consolidated finding and record it."""
        now = format_utc(utc_now())
        with self._db.connect() as conn:
            # Get current severity
            row = conn.execute(
                "SELECT severity FROM consolidated_findings WHERE finding_instance_id = ?",
                (finding_id,),
            ).fetchone()
            if row is None:
                raise PersistenceError(f"Consolidated finding not found: {finding_id}")
            old_severity = row["severity"]

            # Update the finding
            conn.execute(
                "UPDATE consolidated_findings SET severity = ?, updated_at = ? "
                "WHERE finding_instance_id = ?",
                (new_severity.value, now, finding_id),
            )

            # Record the override
            override_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO overrides "
                "(override_id, engagement_id, finding_id, field, old_value, "
                "new_value, reason, actor, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    override_id,
                    engagement_id,
                    finding_id,
                    "severity",
                    old_severity,
                    new_severity.value,
                    reason,
                    actor,
                    now,
                ),
            )
        logger.info(
            "Override severity for %s: %s -> %s (reason: %s)",
            finding_id,
            old_severity,
            new_severity,
            reason,
        )

    def add_manual_finding(
        self,
        engagement_id: str,
        finding: dict[str, Any],
    ) -> str:
        """Add a manually-created finding. Returns the finding_id."""
        finding_id = finding.get("finding_id", str(uuid.uuid4()))
        now = format_utc(utc_now())
        with self._db.connect() as conn:
            conn.execute(
                "INSERT INTO findings "
                "(finding_id, engagement_id, observation_id, finding_key, "
                "tool_source, title, severity, status, category, description, "
                "dedup_keys, benchmark_refs, raw_data, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding_id,
                    engagement_id,
                    finding.get("observation_id", f"manual:{finding_id}"),
                    finding.get("finding_key", f"manual:{finding_id}"),
                    "Manual",
                    finding["title"],
                    finding["severity"],
                    finding.get("status", FindingStatus.FAIL),
                    finding["category"],
                    finding["description"],
                    json.dumps(finding.get("dedup_keys", [f"manual:{finding_id}"])),
                    json.dumps(finding.get("benchmark_refs", [])),
                    json.dumps(finding.get("raw_data", {})),
                    now,
                ),
            )
        logger.info("Added manual finding %s for engagement %s", finding_id, engagement_id)
        return finding_id

    def delete_for_engagement(self, engagement_id: str) -> int:
        """Delete all findings (parsed + consolidated) for an engagement.

        Returns total count of deleted rows.
        """
        total = 0
        with self._db.connect() as conn:
            result = conn.execute(
                "DELETE FROM consolidated_findings WHERE engagement_id = ?",
                (engagement_id,),
            )
            total += result.rowcount
            result = conn.execute(
                "DELETE FROM findings WHERE engagement_id = ?",
                (engagement_id,),
            )
            total += result.rowcount
        return total


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
        with self._db.connect() as conn:
            for r in records:
                conn.execute(
                    "INSERT INTO coverage_records "
                    "(engagement_id, control_id, tool_source, status, reason, "
                    "created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        engagement_id,
                        r["control_id"],
                        r["tool_source"],
                        r["status"],
                        r.get("reason"),
                        now,
                    ),
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
