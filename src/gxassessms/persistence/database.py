"""Database connection management, WAL mode, and migrations runner.

Manages SQLite connections with WAL mode for concurrent reads.
Runs numbered SQL migration files on initialization. The migrations
tracking table (_schema_migrations) records which migrations have
been applied.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from gxassessms.core.contracts.errors import MigrationError

logger = logging.getLogger(__name__)


def get_default_data_dir() -> Path:
    """Return the default data directory for GxAssessMS.

    Respects GXASSESSMS_DATA_DIR environment variable. Falls back to
    ~/.gxassessms/.
    """
    env_dir = os.environ.get("GXASSESSMS_DATA_DIR")
    if env_dir:
        return Path(env_dir)
    return Path.home() / ".gxassessms"


def get_default_db_path() -> Path:
    """Return the default SQLite database path.

    Respects GXASSESSMS_DB_PATH environment variable. Falls back to
    <data_dir>/engagements.db.
    """
    env_path = os.environ.get("GXASSESSMS_DB_PATH")
    if env_path:
        return Path(env_path)
    return get_default_data_dir() / "engagements.db"


def _get_bundled_migrations_dir() -> Path:
    """Return the path to the bundled migrations directory."""
    return Path(__file__).parent / "migrations"


class DatabaseManager:
    """Manages SQLite database connections and schema migrations.

    On initialize():
    1. Creates parent directories if needed
    2. Creates the database file if it doesn't exist
    3. Enables WAL mode and foreign keys
    4. Runs any pending migrations in order
    """

    def __init__(
        self,
        db_path: Path | None = None,
        migrations_dir: Path | None = None,
    ) -> None:
        self._db_path = db_path or get_default_db_path()
        self._migrations_dir = migrations_dir or _get_bundled_migrations_dir()

    @property
    def db_path(self) -> Path:
        return self._db_path

    def initialize(self) -> None:
        """Create DB, enable WAL mode, and run pending migrations."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._ensure_migration_table(conn)
            self._run_pending_migrations(conn)

    @contextmanager
    def connect(self) -> Generator[sqlite3.Connection]:
        """Open a connection with WAL mode, foreign keys, and Row factory."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except sqlite3.OperationalError:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _ensure_migration_table(self, conn: sqlite3.Connection) -> None:
        """Create the migration tracking table if it doesn't exist."""
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS _schema_migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL UNIQUE,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )

    def _run_pending_migrations(self, conn: sqlite3.Connection) -> None:
        """Run all pending migration files in sorted order."""
        if not self._migrations_dir.exists():
            logger.debug("No migrations directory found at %s", self._migrations_dir)
            return

        applied = set(self._get_applied_list(conn))
        migration_files = sorted(
            f
            for f in self._migrations_dir.iterdir()
            if f.suffix == ".sql" and f.name not in applied
        )

        for migration_file in migration_files:
            self._apply_migration(conn, migration_file)

    def _apply_migration(self, conn: sqlite3.Connection, migration_file: Path) -> None:
        """Apply a single migration file."""
        logger.info("Applying migration: %s", migration_file.name)
        sql = migration_file.read_text()
        try:
            conn.executescript(sql)
        except sqlite3.OperationalError as e:
            raise MigrationError(f"Migration {migration_file.name} failed: {e}") from e

        conn.execute(
            "INSERT INTO _schema_migrations (filename) VALUES (?)",
            (migration_file.name,),
        )
        logger.info("Applied migration: %s", migration_file.name)

    def _get_applied_list(self, conn: sqlite3.Connection) -> list[str]:
        """Get list of applied migration filenames in order."""
        rows = conn.execute("SELECT filename FROM _schema_migrations ORDER BY id").fetchall()
        return [row[0] for row in rows]

    def get_applied_migrations(self) -> list[str]:
        """Public API: get list of applied migration filenames."""
        with self.connect() as conn:
            self._ensure_migration_table(conn)
            return self._get_applied_list(conn)
