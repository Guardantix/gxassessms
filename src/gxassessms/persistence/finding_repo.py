"""FindingRepo -- parsed and consolidated findings."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from gxassessms.core.config.datetime_utils import format_utc, utc_now
from gxassessms.core.contracts.errors import PersistenceError
from gxassessms.core.domain.enums import Category, FindingStatus, Severity, ToolSource
from gxassessms.core.domain.models import (
    ConfidenceScore,
    ConsolidatedFinding,
    Finding,
    SourceEvidence,
)
from gxassessms.persistence.database import DatabaseManager

logger = logging.getLogger(__name__)


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
        records = [
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
            )
            for f in findings
        ]
        with self._db.connect() as conn:
            conn.executemany(
                "INSERT INTO findings "
                "(finding_id, engagement_id, observation_id, finding_key, "
                "tool_source, title, severity, status, category, description, "
                "dedup_keys, benchmark_refs, raw_data, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                records,
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
        records = [
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
            )
            for f in findings
        ]
        with self._db.connect() as conn:
            conn.executemany(
                "INSERT INTO consolidated_findings "
                "(finding_instance_id, engagement_id, finding_key, title, "
                "severity, status, category, description, sources, "
                "confidence, benchmark_refs, root_cause, remediation, "
                "narrative, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                records,
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

    def save_parsed_findings(self, engagement_id: str, findings: list[Finding]) -> None:
        """Persist parsed findings, replacing any prior batch for this engagement.

        DELETE + INSERT run in a single transaction: either both commit or
        both roll back. Callers must not use save_parsed() for new code --
        that method accumulates rows.
        """
        now = format_utc(utc_now())
        records = [
            (
                str(uuid.uuid4()),
                engagement_id,
                f.observation_id,
                f.native_check_id,
                f.finding_key,
                f.tool.value,
                f.title,
                f.severity.value,
                f.status.value,
                f.category.value,
                f.description,
                json.dumps(f.dedup_keys),
                json.dumps(f.benchmark_refs),
                json.dumps(f.raw_data),
                now,
            )
            for f in findings
        ]
        with self._db.connect() as conn:
            conn.execute(
                "DELETE FROM findings WHERE engagement_id = ? AND tool_source != ?",
                (engagement_id, ToolSource.MANUAL.value),
            )
            conn.executemany(
                "INSERT INTO findings "
                "(finding_id, engagement_id, observation_id, native_check_id, "
                "finding_key, tool_source, title, severity, status, category, "
                "description, dedup_keys, benchmark_refs, raw_data, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                records,
            )

    def save_consolidated_findings(
        self, engagement_id: str, findings: list[ConsolidatedFinding]
    ) -> None:
        """Persist consolidated findings, replacing any prior batch for this engagement.

        Preserves finding_instance_id for existing finding_keys so that
        override records and event log entries remain linked.
        """
        now = format_utc(utc_now())
        with self._db.connect() as conn:
            existing_rows = conn.execute(
                "SELECT finding_key, finding_instance_id FROM consolidated_findings "
                "WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
            existing_ids = {row["finding_key"]: row["finding_instance_id"] for row in existing_rows}

            conn.execute(
                "DELETE FROM consolidated_findings WHERE engagement_id = ?",
                (engagement_id,),
            )

            records = [
                (
                    existing_ids.get(f.finding_key, f.finding_instance_id),
                    engagement_id,
                    f.finding_key,
                    f.title,
                    f.severity.value,
                    f.status.value,
                    f.category.value,
                    f.description,
                    json.dumps([s.model_dump(mode="json") for s in f.sources]),
                    json.dumps(f.confidence.model_dump(mode="json")),
                    json.dumps(f.benchmark_refs),
                    f.root_cause,
                    f.remediation,
                    f.narrative,
                    now,
                )
                for f in findings
            ]
            conn.executemany(
                "INSERT INTO consolidated_findings "
                "(finding_instance_id, engagement_id, finding_key, title, "
                "severity, status, category, description, sources, "
                "confidence, benchmark_refs, root_cause, remediation, "
                "narrative, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                records,
            )

    def get_parsed_as_findings(self, engagement_id: str) -> list[Finding]:
        """Load parsed findings from DB and reconstruct Finding domain objects.

        Returns [] (not raises) when no findings exist -- empty is valid
        (all controls passed).
        """
        rows = self.get_parsed(engagement_id)
        return [
            Finding(
                observation_id=row["observation_id"],
                native_check_id=row.get("native_check_id") or "",
                finding_key=row["finding_key"],
                tool=ToolSource(row["tool_source"]),
                title=row["title"],
                severity=Severity(row["severity"]),
                status=FindingStatus(row["status"]),
                category=Category(row["category"]),
                description=row["description"],
                dedup_keys=json.loads(row.get("dedup_keys") or "[]"),
                benchmark_refs=json.loads(row.get("benchmark_refs") or "[]"),
                raw_data=json.loads(row.get("raw_data") or "{}"),
            )
            for row in rows
        ]

    def get_consolidated_as_findings(self, engagement_id: str) -> list[ConsolidatedFinding]:
        """Load consolidated findings from DB and reconstruct domain objects."""
        rows = self.get_consolidated(engagement_id)
        return [
            ConsolidatedFinding(
                finding_instance_id=row["finding_instance_id"],
                finding_key=row["finding_key"],
                title=row["title"],
                severity=Severity(row["severity"]),
                status=FindingStatus(row["status"]),
                category=Category(row["category"]),
                description=row["description"],
                sources=[
                    SourceEvidence.model_validate(s) for s in json.loads(row.get("sources") or "[]")
                ],
                confidence=ConfidenceScore.model_validate(
                    json.loads(row.get("confidence") or "{}")
                ),
                benchmark_refs=json.loads(row.get("benchmark_refs") or "[]"),
                root_cause=row.get("root_cause"),
                remediation=row.get("remediation"),
                narrative=row.get("narrative"),
            )
            for row in rows
        ]

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
            # Scoped to engagement to prevent cross-engagement mutation
            row = conn.execute(
                "SELECT severity FROM consolidated_findings "
                "WHERE finding_instance_id = ? AND engagement_id = ?",
                (finding_id, engagement_id),
            ).fetchone()
            if row is None:
                raise PersistenceError(f"Consolidated finding not found: {finding_id}")
            old_severity = row["severity"]

            conn.execute(
                "UPDATE consolidated_findings SET severity = ?, updated_at = ? "
                "WHERE finding_instance_id = ? AND engagement_id = ?",
                (new_severity.value, now, finding_id, engagement_id),
            )

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
                    ToolSource.MANUAL.value,
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
