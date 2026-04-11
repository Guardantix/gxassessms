"""Unit tests for pipeline/config_snapshot_mirror.py."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from gxassessms.core.contracts.errors import (
    ConfigSnapshotMirrorError,
    PersistenceError,
)
from gxassessms.pipeline.config_snapshot_mirror import (
    _do_mirror,
    mirror_config_snapshot_from_db,
)


class TestDoMirrorInternal:
    """Narrow tests that exercise the raising inner function."""

    def test_happy_path_json_string(self) -> None:
        repo = MagicMock()
        repo.get.return_value = {
            "config_snapshot": json.dumps({"client_name": "Acme", "tools": {}})
        }
        am = MagicMock()
        _do_mirror(repo, am, "eng-1")
        am.write_config_snapshot.assert_called_once_with(
            "eng-1", {"client_name": "Acme", "tools": {}}
        )

    def test_happy_path_prehydrated_dict(self) -> None:
        repo = MagicMock()
        repo.get.return_value = {"config_snapshot": {"client_name": "Acme", "tools": {}}}
        am = MagicMock()
        _do_mirror(repo, am, "eng-2")
        am.write_config_snapshot.assert_called_once_with(
            "eng-2", {"client_name": "Acme", "tools": {}}
        )

    def test_missing_db_row_raises(self) -> None:
        repo = MagicMock()
        repo.get.side_effect = PersistenceError("not found")
        with pytest.raises(ConfigSnapshotMirrorError, match="lookup failed"):
            _do_mirror(repo, MagicMock(), "eng-gone")

    def test_sqlite_error_wraps_to_mirror_error(self) -> None:
        import sqlite3

        repo = MagicMock()
        repo.get.side_effect = sqlite3.OperationalError("database is locked")
        with pytest.raises(ConfigSnapshotMirrorError, match="lookup failed"):
            _do_mirror(repo, MagicMock(), "eng-locked")

    def test_null_snapshot_raises(self) -> None:
        repo = MagicMock()
        repo.get.return_value = {"config_snapshot": None}
        with pytest.raises(ConfigSnapshotMirrorError, match="unparseable") as exc_info:
            _do_mirror(repo, MagicMock(), "eng-null")
        assert exc_info.value.engagement_id == "eng-null"
        assert exc_info.value.__cause__ is not None

    def test_corrupt_json_raises(self) -> None:
        repo = MagicMock()
        repo.get.return_value = {"config_snapshot": "not-json"}
        with pytest.raises(ConfigSnapshotMirrorError, match="unparseable"):
            _do_mirror(repo, MagicMock(), "eng-corrupt")

    def test_missing_client_name_raises(self) -> None:
        repo = MagicMock()
        repo.get.return_value = {"config_snapshot": "{}"}
        with pytest.raises(ConfigSnapshotMirrorError, match="missing client_name") as exc_info:
            _do_mirror(repo, MagicMock(), "eng-headerless")
        assert exc_info.value.engagement_id == "eng-headerless"

    @pytest.mark.parametrize("client_name", ["", "   ", "\t\n", None, 42])
    def test_empty_whitespace_or_nonstring_client_name_raises(self, client_name: object) -> None:
        repo = MagicMock()
        snapshot: dict[str, Any]
        if client_name is None:
            snapshot = {"tools": {}}
        else:
            snapshot = {"client_name": client_name, "tools": {}}
        repo.get.return_value = {"config_snapshot": json.dumps(snapshot)}
        with pytest.raises(ConfigSnapshotMirrorError, match="missing client_name"):
            _do_mirror(repo, MagicMock(), "eng-blank")

    def test_write_io_error_raises(self) -> None:
        repo = MagicMock()
        repo.get.return_value = {"config_snapshot": json.dumps({"client_name": "Acme"})}
        am = MagicMock()
        am.write_config_snapshot.side_effect = OSError("disk full")
        with pytest.raises(ConfigSnapshotMirrorError, match="disk full"):
            _do_mirror(repo, am, "eng-nodisk")


class TestMirrorFailOpenContract:
    """Public entry point: never raises, logs ERROR on failure."""

    def test_failure_is_swallowed_and_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        repo = MagicMock()
        repo.get.side_effect = PersistenceError("not found")
        with caplog.at_level("ERROR"):
            mirror_config_snapshot_from_db(repo, MagicMock(), "eng-gone")
        assert "Failed to mirror config_snapshot" in caplog.text

    def test_log_message_includes_remediation_command(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        repo = MagicMock()
        repo.get.side_effect = PersistenceError("not found")
        with caplog.at_level("ERROR"):
            mirror_config_snapshot_from_db(repo, MagicMock(), "eng-gone")
        assert "mseco collect --engagement-id eng-gone" in caplog.text

    def test_unexpected_exception_still_swallowed(self, caplog: pytest.LogCaptureFixture) -> None:
        repo = MagicMock()
        repo.get.side_effect = RuntimeError("totally unexpected")
        with caplog.at_level("ERROR"):
            mirror_config_snapshot_from_db(repo, MagicMock(), "eng-chaos")
        assert "Unexpected failure mirroring config_snapshot" in caplog.text
        assert "RuntimeError" in caplog.text

    def test_success_is_quiet(self, caplog: pytest.LogCaptureFixture) -> None:
        repo = MagicMock()
        repo.get.return_value = {"config_snapshot": json.dumps({"client_name": "Acme"})}
        am = MagicMock()
        with caplog.at_level("ERROR"):
            mirror_config_snapshot_from_db(repo, am, "eng-ok")
        assert caplog.text == ""
        am.write_config_snapshot.assert_called_once()
