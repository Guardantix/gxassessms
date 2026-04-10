"""Tests for schema definition and initial migration."""

import sqlite3
from pathlib import Path
from typing import ClassVar

import pytest

from gxassessms.persistence.database import DatabaseManager


@pytest.fixture
def db_manager(tmp_path: Path) -> DatabaseManager:
    """Create a DatabaseManager with the real migration files."""
    db_path = tmp_path / "test.db"
    migrations_dir = Path(__file__).parent.parent.parent.parent / (
        "src/gxassessms/persistence/migrations"
    )
    mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
    mgr.initialize()
    return mgr


class TestSchemaTablesExist:
    EXPECTED_TABLES: ClassVar[list[str]] = [
        "engagements",
        "findings",
        "consolidated_findings",
        "coverage_records",
        "tool_run_results",
        "pipeline_events",
        "overrides",
        "stage_history",
        "longitudinal_snapshots",
    ]

    @pytest.mark.parametrize("table_name", EXPECTED_TABLES)
    def test_table_exists(self, db_manager: DatabaseManager, table_name: str) -> None:
        with db_manager.connect() as conn:
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,),
            ).fetchone()
            assert result is not None, f"Table {table_name} does not exist"


class TestSchemaIndexes:
    def test_idx_findings_severity_category(self, db_manager: DatabaseManager) -> None:
        with db_manager.connect() as conn:
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name='idx_findings_severity_category'"
            ).fetchone()
            assert result is not None

    def test_idx_findings_engagement_severity(self, db_manager: DatabaseManager) -> None:
        with db_manager.connect() as conn:
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name='idx_findings_engagement_severity'"
            ).fetchone()
            assert result is not None

    def test_idx_findings_tool_check(self, db_manager: DatabaseManager) -> None:
        with db_manager.connect() as conn:
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name='idx_findings_tool_check'"
            ).fetchone()
            assert result is not None

    def test_idx_pipeline_events_engagement_timestamp(self, db_manager: DatabaseManager) -> None:
        with db_manager.connect() as conn:
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name='idx_pipeline_events_engagement_timestamp'"
            ).fetchone()
            assert result is not None

    def test_idx_pipeline_events_engagement_event_type(self, db_manager: DatabaseManager) -> None:
        with db_manager.connect() as conn:
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name='idx_pipeline_events_engagement_event_type'"
            ).fetchone()
            assert result is not None

    def test_idx_longitudinal_snapshots_engagement_is_unique(
        self, db_manager: DatabaseManager
    ) -> None:
        with db_manager.connect() as conn:
            result = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='index' "
                "AND name='idx_longitudinal_snapshots_engagement'"
            ).fetchone()
            assert result is not None
            index_ddl: str = result["sql"]
            assert "UNIQUE" in index_ddl.upper()


class TestSchemaConstraints:
    def test_engagements_state_check_constraint(self, db_manager: DatabaseManager) -> None:
        """Inserting an invalid state should fail."""
        with db_manager.connect() as conn, pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO engagements (engagement_id, client_name, tenant_id, "
                "state, created_at, config_snapshot) "
                "VALUES (?, ?, ?, ?, datetime('now'), ?)",
                ("eng-001", "Test", "tenant-001", "INVALID_STATE", "{}"),
            )

    def test_findings_severity_check_constraint(self, db_manager: DatabaseManager) -> None:
        """Inserting an invalid severity should fail."""
        with db_manager.connect() as conn:
            # First create an engagement
            conn.execute(
                "INSERT INTO engagements (engagement_id, client_name, tenant_id, "
                "state, created_at, config_snapshot) "
                "VALUES (?, ?, ?, ?, datetime('now'), ?)",
                ("eng-001", "Test", "tenant-001", "CREATED", "{}"),
            )
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO findings (finding_id, engagement_id, observation_id, "
                    "finding_key, tool_source, title, severity, status, category, "
                    "description, dedup_keys, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                    (
                        "f-001",
                        "eng-001",
                        "obs-001",
                        "key-001",
                        "ScubaGear",
                        "Test",
                        "INVALID",
                        "FAIL",
                        "Identity & Access",
                        "desc",
                        "[]",
                    ),
                )

    def test_pipeline_events_are_insertable(self, db_manager: DatabaseManager) -> None:
        with db_manager.connect() as conn:
            conn.execute(
                "INSERT INTO engagements (engagement_id, client_name, tenant_id, "
                "state, created_at, config_snapshot) "
                "VALUES (?, ?, ?, ?, datetime('now'), ?)",
                ("eng-001", "Test", "tenant-001", "CREATED", "{}"),
            )
            conn.execute(
                "INSERT INTO pipeline_events (event_id, engagement_id, timestamp, "
                "event_type, actor, payload) "
                "VALUES (?, ?, datetime('now'), ?, ?, ?)",
                ("evt-001", "eng-001", "state_transition", "system", "{}"),
            )
            result = conn.execute(
                "SELECT * FROM pipeline_events WHERE event_id=?", ("evt-001",)
            ).fetchone()
            assert result is not None

    def test_longitudinal_snapshot_duplicate_engagement_date_rejected(
        self, db_manager: DatabaseManager
    ) -> None:
        """Two snapshots for the same (engagement_id, snapshot_date) must be rejected."""
        with db_manager.connect() as conn:
            conn.execute(
                "INSERT INTO engagements (engagement_id, client_name, tenant_id, "
                "state, created_at, config_snapshot) "
                "VALUES (?, ?, ?, ?, datetime('now'), ?)",
                ("eng-001", "Test", "tenant-001", "CREATED", "{}"),
            )
            conn.execute(
                "INSERT INTO longitudinal_snapshots "
                "(engagement_id, snapshot_date, total_findings, created_at) "
                "VALUES (?, '2026-01-01', ?, datetime('now'))",
                ("eng-001", 0),
            )
            # A second snapshot on the same date must be rejected
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO longitudinal_snapshots "
                    "(engagement_id, snapshot_date, total_findings, created_at) "
                    "VALUES (?, '2026-01-01', ?, datetime('now'))",
                    ("eng-001", 5),
                )
            # But a snapshot on a different date must be allowed (trend tracking)
            conn.execute(
                "INSERT INTO longitudinal_snapshots "
                "(engagement_id, snapshot_date, total_findings, created_at) "
                "VALUES (?, '2026-02-01', ?, datetime('now'))",
                ("eng-001", 10),
            )
            result = conn.execute(
                "SELECT total_findings FROM longitudinal_snapshots "
                "WHERE engagement_id = ? AND snapshot_date = '2026-02-01'",
                ("eng-001",),
            ).fetchone()
            assert result is not None
            assert result["total_findings"] == 10

    def test_overrides_foreign_key_to_engagement(self, db_manager: DatabaseManager) -> None:
        """Overrides with a non-existent engagement_id should fail."""
        with db_manager.connect() as conn, pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO overrides (override_id, engagement_id, finding_id, "
                "field, old_value, new_value, reason, actor, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                (
                    "ovr-001",
                    "nonexistent-eng",
                    "f-001",
                    "severity",
                    "MEDIUM",
                    "HIGH",
                    "reason",
                    "human:rick",
                ),
            )


class TestEnumSchemaSync:
    def test_engagement_state_check_matches_enum(self) -> None:
        """CHECK constraint values in schema.sql must match EngagementState enum."""
        import re

        from gxassessms.pipeline.state import EngagementState

        schema_path = (
            Path(__file__).parent.parent.parent.parent / "src/gxassessms/persistence/schema.sql"
        )
        schema_text = schema_path.read_text()

        # Extract the state CHECK constraint values
        match = re.search(
            r"state\s+TEXT\s+NOT\s+NULL\s+CHECK\s*\(state\s+IN\s*\((.*?)\)\)",
            schema_text,
            re.DOTALL,
        )
        assert match is not None, "Could not find state CHECK constraint in schema.sql"

        check_values = {v.strip().strip("'") for v in match.group(1).split(",")}
        enum_values = {s.value for s in EngagementState}

        assert check_values == enum_values, (
            f"Schema CHECK constraint {check_values} does not match "
            f"EngagementState enum {enum_values}"
        )


class TestSchemaAndMigrationSync:
    def test_schema_sql_matches_migration(self) -> None:
        """schema.sql and 001_initial.sql should have identical content."""
        base = Path(__file__).parent.parent.parent.parent / "src/gxassessms/persistence"
        schema_content = (base / "schema.sql").read_text().strip()
        migration_content = (base / "migrations" / "001_initial.sql").read_text().strip()
        assert schema_content == migration_content, "schema.sql and 001_initial.sql are out of sync"
