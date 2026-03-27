"""Tests for database connection management and migrations runner."""

import sqlite3
from pathlib import Path

import pytest

from gxassessms.core.contracts.errors import MigrationError
from gxassessms.persistence.database import (
    DatabaseManager,
    get_default_data_dir,
    get_default_db_path,
)


class TestDefaultPaths:
    def test_default_data_dir_uses_home(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GXASSESSMS_DATA_DIR", raising=False)
        monkeypatch.delenv("GXASSESSMS_DB_PATH", raising=False)
        data_dir = get_default_data_dir()
        assert str(data_dir).endswith(".gxassessms")

    def test_data_dir_respects_env_var(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        custom_dir = tmp_path / "custom-data"
        monkeypatch.setenv("GXASSESSMS_DATA_DIR", str(custom_dir))
        data_dir = get_default_data_dir()
        assert data_dir == custom_dir

    def test_default_db_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GXASSESSMS_DB_PATH", raising=False)
        monkeypatch.delenv("GXASSESSMS_DATA_DIR", raising=False)
        db_path = get_default_db_path()
        assert db_path.name == "engagements.db"

    def test_db_path_respects_env_var(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        custom_db = tmp_path / "custom.db"
        monkeypatch.setenv("GXASSESSMS_DB_PATH", str(custom_db))
        db_path = get_default_db_path()
        assert db_path == custom_db


class TestDatabaseManager:
    def test_init_creates_db_file(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
        mgr.initialize()
        assert db_path.exists()

    def test_wal_mode_enabled(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
        mgr.initialize()
        with mgr.connect() as conn:
            result = conn.execute("PRAGMA journal_mode").fetchone()
            assert result[0] == "wal"

    def test_foreign_keys_enabled(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
        mgr.initialize()
        with mgr.connect() as conn:
            result = conn.execute("PRAGMA foreign_keys").fetchone()
            assert result[0] == 1

    def test_runs_migrations_on_initialize(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        (migrations_dir / "001_test.sql").write_text(
            "CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT);"
        )
        mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
        mgr.initialize()
        with mgr.connect() as conn:
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='test_table'"
            ).fetchone()
            assert result is not None

    def test_tracks_applied_migrations(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        (migrations_dir / "001_first.sql").write_text(
            "CREATE TABLE first_table (id INTEGER PRIMARY KEY);"
        )
        mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
        mgr.initialize()
        applied = mgr.get_applied_migrations()
        assert "001_first.sql" in applied

    def test_skips_already_applied_migrations(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        (migrations_dir / "001_first.sql").write_text(
            "CREATE TABLE first_table (id INTEGER PRIMARY KEY);"
        )
        mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
        mgr.initialize()
        # Running initialize again should not fail (migration already applied)
        mgr.initialize()
        applied = mgr.get_applied_migrations()
        assert applied.count("001_first.sql") == 1

    def test_runs_migrations_in_order(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        (migrations_dir / "001_first.sql").write_text(
            "CREATE TABLE first_table (id INTEGER PRIMARY KEY);"
        )
        (migrations_dir / "002_second.sql").write_text(
            "CREATE TABLE second_table (id INTEGER PRIMARY KEY, "
            "first_id INTEGER REFERENCES first_table(id));"
        )
        mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
        mgr.initialize()
        applied = mgr.get_applied_migrations()
        assert applied == ["001_first.sql", "002_second.sql"]

    def test_bad_migration_raises_migration_error(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        (migrations_dir / "001_bad.sql").write_text("THIS IS NOT VALID SQL !!!")
        mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
        with pytest.raises(MigrationError):
            mgr.initialize()

    def test_connect_returns_connection(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
        mgr.initialize()
        with mgr.connect() as conn:
            assert isinstance(conn, sqlite3.Connection)

    def test_connect_sets_row_factory(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
        mgr.initialize()
        with mgr.connect() as conn:
            assert conn.row_factory == sqlite3.Row

    def test_connect_rolls_back_on_database_error(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        (migrations_dir / "001_test.sql").write_text(
            "CREATE TABLE rollback_test (id INTEGER PRIMARY KEY, name TEXT);"
        )
        mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
        mgr.initialize()

        def _insert_with_duplicate(m: DatabaseManager) -> None:
            with m.connect() as conn:
                conn.execute("INSERT INTO rollback_test (id, name) VALUES (1, 'before')")
                conn.execute("INSERT INTO rollback_test (id, name) VALUES (1, 'duplicate')")

        with pytest.raises(sqlite3.DatabaseError):
            _insert_with_duplicate(mgr)
        # The insert should have been rolled back
        with mgr.connect() as conn:
            rows = conn.execute("SELECT * FROM rollback_test").fetchall()
            assert len(rows) == 0

    def test_missing_migrations_dir_no_error(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        nonexistent_dir = tmp_path / "no-such-dir"
        mgr = DatabaseManager(db_path=db_path, migrations_dir=nonexistent_dir)
        mgr.initialize()
        assert db_path.exists()

    def test_parent_directory_created_if_missing(self, tmp_path: Path) -> None:
        db_path = tmp_path / "subdir" / "nested" / "test.db"
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
        mgr.initialize()
        assert db_path.exists()
