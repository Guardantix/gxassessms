"""Seed a snapshot engagement DB from sanitized representative data.

Used by tests/integration/test_migrations.py to populate a tmp_path DB
with realistic data before re-running migrations, verifying that existing
rows are preserved across migration application.

This module intentionally uses the public repository API rather than raw
SQL inserts, so the seed data stays in sync with schema evolution.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from gxassessms.core.config.datetime_utils import format_utc, utc_now
from gxassessms.persistence import (
    DatabaseManager,
    EngagementRepo,
    EventRepo,
)
from gxassessms.pipeline.state import PipelineEvent

SNAPSHOT_TENANT = "snapshot-tenant-00000000-0000-0000-0000-000000000000"
SNAPSHOT_CLIENT_NAME = "Snapshot Test Client"


def seed_snapshot_db(db_path: Path) -> str:
    """Initialize a DB at db_path and insert sanitized snapshot data.

    Returns the engagement_id of the seeded engagement.
    """
    db = DatabaseManager(db_path=db_path)
    db.initialize()

    engagement_repo = EngagementRepo(db)
    event_repo = EventRepo(db)

    config_snapshot: dict[str, Any] = {
        "client_name": SNAPSHOT_CLIENT_NAME,
        "tenant_id": SNAPSHOT_TENANT,
        "tools": {"scubagear": {"enabled": True}},
    }

    engagement_id = engagement_repo.create(
        client_name=SNAPSHOT_CLIENT_NAME,
        tenant_id=SNAPSHOT_TENANT,
        config_snapshot=config_snapshot,
    )

    # Seed a representative pipeline event
    event_repo.append(
        PipelineEvent(
            event_id=str(uuid.uuid4()),
            engagement_id=engagement_id,
            timestamp=utc_now(),
            event_type="state_transition",
            actor="seed-script",
            payload={"from": "CREATED", "to": "COLLECTING"},
        )
    )

    # Seed a tool_run_results row via raw DB write (no repo for this table)
    with db.connect() as conn:
        conn.execute(
            """
            INSERT INTO tool_run_results (
                engagement_id, tool_source, started_at, completed_at,
                status, finding_count, error, duration_seconds
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                "SCUBAGEAR",
                format_utc(utc_now()),
                format_utc(utc_now()),
                "SUCCESS",
                15,
                None,
                42.5,
            ),
        )

    return engagement_id
