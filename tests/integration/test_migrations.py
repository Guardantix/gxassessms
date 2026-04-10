"""Database migration tests -- DatabaseManager against seeded snapshot.

Exercises the real DatabaseManager.initialize() path including the
_schema_migrations tracker. Verifies:
  - Fresh init applies all bundled migrations cleanly
  - Re-initialization is idempotent (no migrations re-applied)
  - Seeded data survives re-initialization
  - Post-migration schema matches schema.sql (canonical reference)
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import gxassessms.persistence as _persist
from gxassessms.persistence import DatabaseManager
from tests.fixtures.engagements.seed_snapshot import (
    SNAPSHOT_CLIENT_NAME,
    SNAPSHOT_TENANT,
    seed_snapshot_db,
)

# Locate schema.sql and migrations/ relative to the installed package so
# the tests remain correct if the test file itself moves.
_PERSIST_DIR = Path(_persist.__file__).parent
SCHEMA_SQL_PATH = _PERSIST_DIR / "schema.sql"
MIGRATIONS_DIR = _PERSIST_DIR / "migrations"


# Helpers ---------------------------------------------------------------


def _get_user_tables(conn: sqlite3.Connection) -> set[str]:
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )
    return {row[0] for row in cursor.fetchall()}


def _get_user_indexes(conn: sqlite3.Connection) -> set[str]:
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
    )
    return {row[0] for row in cursor.fetchall()}


def _get_table_column_attrs(
    conn: sqlite3.Connection, table: str
) -> set[tuple[str, str, int, str | None, int]]:
    """Return each column as (name, type, notnull, default_value, pk).

    The tuple deliberately omits the column ordinal (cid) so rearrangement
    is tolerated, but catches drift in type, NOT NULL, DEFAULT, and primary
    key flags -- all of which the plain name-only comparison would miss.
    """
    cursor = conn.execute(f"PRAGMA table_info({table})")
    return {
        (row[1], row[2], row[3], row[4], row[5])  # name, type, notnull, dflt, pk
        for row in cursor.fetchall()
    }


# Tests -----------------------------------------------------------------


class TestMigrationsApplyCleanly:
    """Fresh init runs all bundled migrations without error."""

    def test_fresh_init_runs_all_migrations(self, tmp_path: Path) -> None:
        db_path = tmp_path / "fresh.db"
        db = DatabaseManager(db_path=db_path)
        db.initialize()

        applied = db.get_applied_migrations()
        migration_files = sorted(f.name for f in MIGRATIONS_DIR.glob("*.sql"))
        assert applied == migration_files, (
            f"Applied migrations {applied} do not match available "
            f"migration files {migration_files}."
        )

    def test_reinit_is_idempotent(self, tmp_path: Path) -> None:
        db_path = tmp_path / "idempotent.db"
        db1 = DatabaseManager(db_path=db_path)
        db1.initialize()
        first_applied = db1.get_applied_migrations()

        # Second initialize() on the same DB should be a no-op
        db2 = DatabaseManager(db_path=db_path)
        db2.initialize()
        second_applied = db2.get_applied_migrations()

        assert first_applied == second_applied
        with db2.connect() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM _schema_migrations")
            count = cursor.fetchone()[0]
        assert count == len(first_applied)


class TestSeededDataSurvives:
    """Seeded rows persist across DatabaseManager re-initialization."""

    def test_seeded_engagement_survives_reinit(self, tmp_path: Path) -> None:
        db_path = tmp_path / "seeded.db"
        engagement_id = seed_snapshot_db(db_path)

        # Re-initialize (simulating a fresh process attaching to the DB)
        db2 = DatabaseManager(db_path=db_path)
        db2.initialize()
        with db2.connect() as conn:
            cursor = conn.execute(
                "SELECT engagement_id, client_name, tenant_id "
                "FROM engagements WHERE engagement_id = ?",
                (engagement_id,),
            )
            row = cursor.fetchone()
        assert row is not None, "Seeded engagement lost after reinit"
        assert row["client_name"] == SNAPSHOT_CLIENT_NAME
        assert row["tenant_id"] == SNAPSHOT_TENANT

    def test_seeded_pipeline_event_survives(self, tmp_path: Path) -> None:
        db_path = tmp_path / "seeded_events.db"
        engagement_id = seed_snapshot_db(db_path)
        db2 = DatabaseManager(db_path=db_path)
        db2.initialize()
        with db2.connect() as conn:
            cursor = conn.execute(
                "SELECT event_type FROM pipeline_events WHERE engagement_id = ?",
                (engagement_id,),
            )
            rows = cursor.fetchall()
        assert len(rows) >= 1
        assert any(r["event_type"] == "state_transition" for r in rows)

    def test_seeded_tool_run_result_survives(self, tmp_path: Path) -> None:
        db_path = tmp_path / "seeded_tools.db"
        engagement_id = seed_snapshot_db(db_path)
        db2 = DatabaseManager(db_path=db_path)
        db2.initialize()
        with db2.connect() as conn:
            cursor = conn.execute(
                "SELECT tool_source, status, finding_count "
                "FROM tool_run_results WHERE engagement_id = ?",
                (engagement_id,),
            )
            rows = cursor.fetchall()
        assert len(rows) == 1
        assert rows[0]["tool_source"] == "SCUBAGEAR"
        assert rows[0]["status"] == "SUCCESS"


class TestSchemaMatchesCanonical:
    """Migrated schema matches schema.sql (current-state reference)."""

    def test_same_tables_as_schema_sql(self, tmp_path: Path) -> None:
        # Apply migrations
        migrated_path = tmp_path / "migrated.db"
        DatabaseManager(db_path=migrated_path).initialize()

        # Create a fresh DB from schema.sql alone
        fresh_path = tmp_path / "fresh_from_schema.db"
        fresh_conn = sqlite3.connect(str(fresh_path))
        fresh_conn.executescript(SCHEMA_SQL_PATH.read_text(encoding="utf-8"))
        fresh_conn.commit()

        migrated_conn = sqlite3.connect(str(migrated_path))
        migrated_conn.row_factory = sqlite3.Row

        migrated_tables = _get_user_tables(migrated_conn) - {"_schema_migrations"}
        fresh_tables = _get_user_tables(fresh_conn)

        assert migrated_tables == fresh_tables, (
            f"Table set mismatch:\n"
            f"  Only in migrated DB: {sorted(migrated_tables - fresh_tables)}\n"
            f"  Only in schema.sql: {sorted(fresh_tables - migrated_tables)}"
        )

        fresh_conn.close()
        migrated_conn.close()

    def test_same_columns_per_table(self, tmp_path: Path) -> None:
        migrated_path = tmp_path / "migrated2.db"
        DatabaseManager(db_path=migrated_path).initialize()
        fresh_path = tmp_path / "fresh2.db"
        fresh_conn = sqlite3.connect(str(fresh_path))
        fresh_conn.executescript(SCHEMA_SQL_PATH.read_text(encoding="utf-8"))
        fresh_conn.commit()

        migrated_conn = sqlite3.connect(str(migrated_path))
        migrated_conn.row_factory = sqlite3.Row

        fresh_tables = _get_user_tables(fresh_conn)
        for table in fresh_tables:
            migrated_cols = _get_table_column_attrs(migrated_conn, table)
            fresh_cols = _get_table_column_attrs(fresh_conn, table)
            assert migrated_cols == fresh_cols, (
                f"Column attribute mismatch for table {table!r}:\n"
                f"  Only in migrated: {sorted(migrated_cols - fresh_cols)}\n"
                f"  Only in schema.sql: {sorted(fresh_cols - migrated_cols)}"
            )

        fresh_conn.close()
        migrated_conn.close()

    def test_same_indexes(self, tmp_path: Path) -> None:
        migrated_path = tmp_path / "migrated3.db"
        DatabaseManager(db_path=migrated_path).initialize()
        fresh_path = tmp_path / "fresh3.db"
        fresh_conn = sqlite3.connect(str(fresh_path))
        fresh_conn.executescript(SCHEMA_SQL_PATH.read_text(encoding="utf-8"))
        fresh_conn.commit()

        migrated_conn = sqlite3.connect(str(migrated_path))
        migrated_indexes = _get_user_indexes(migrated_conn)
        fresh_indexes = _get_user_indexes(fresh_conn)

        assert migrated_indexes == fresh_indexes, (
            f"Index set mismatch:\n"
            f"  Only in migrated: {sorted(migrated_indexes - fresh_indexes)}\n"
            f"  Only in schema.sql: {sorted(fresh_indexes - migrated_indexes)}"
        )

        fresh_conn.close()
        migrated_conn.close()
