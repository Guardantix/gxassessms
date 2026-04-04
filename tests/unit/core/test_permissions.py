"""Tests for directory permission hardening (secure_mkdir, check, warn)."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from gxassessms.core.security.permissions import (
    check_directory_permissions,
    secure_mkdir,
    warn_broad_permissions,
)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
class TestSecureMkdir:
    """Tests for secure_mkdir -- directory creation with restrictive mode."""

    def test_creates_directory_with_restrictive_mode(self, tmp_path: Path) -> None:
        target = tmp_path / "data"
        secure_mkdir(target)
        assert target.stat().st_mode & 0o777 == 0o700

    def test_creates_parents_with_restrictive_mode(self, tmp_path: Path) -> None:
        # a/b/c where only tmp_path exists
        # Set tmp_path to a known non-0o700 mode so we can verify it is untouched
        tmp_path.chmod(0o755)
        target = tmp_path / "a" / "b" / "c"
        secure_mkdir(target, parents=True)
        assert (tmp_path / "a").stat().st_mode & 0o777 == 0o700
        assert (tmp_path / "a" / "b").stat().st_mode & 0o777 == 0o700
        assert target.stat().st_mode & 0o777 == 0o700
        # tmp_path itself should NOT have been chmod'd
        assert tmp_path.stat().st_mode & 0o777 == 0o755

    def test_parents_partial_existing(self, tmp_path: Path) -> None:
        # a/b already exists at 0o755; create a/b/c
        ab = tmp_path / "a" / "b"
        ab.mkdir(parents=True)
        ab.chmod(0o755)
        target = ab / "c"
        secure_mkdir(target, parents=True)
        assert target.stat().st_mode & 0o777 == 0o700
        assert ab.stat().st_mode & 0o777 == 0o755  # unchanged

    def test_exist_ok_tightens_existing_permissions(self, tmp_path: Path) -> None:
        target = tmp_path / "data"
        target.mkdir()
        target.chmod(0o755)
        secure_mkdir(target, exist_ok=True)
        assert target.stat().st_mode & 0o777 == 0o700

    def test_raises_file_exists_when_not_exist_ok(self, tmp_path: Path) -> None:
        target = tmp_path / "data"
        target.mkdir()
        target.chmod(0o755)
        with pytest.raises(FileExistsError):
            secure_mkdir(target, exist_ok=False)
        # mode should be unchanged since chmod never ran
        assert target.stat().st_mode & 0o777 == 0o755

    def test_leaf_only_with_parents_flag(self, tmp_path: Path) -> None:
        # parent already exists; parents=True but only leaf is new
        parent = tmp_path / "existing"
        parent.mkdir()
        parent.chmod(0o755)
        target = parent / "new"
        secure_mkdir(target, parents=True)
        assert target.stat().st_mode & 0o777 == 0o700
        assert parent.stat().st_mode & 0o777 == 0o755  # unchanged

    def test_chmod_failure_propagates_oserror(self, tmp_path: Path) -> None:
        target = tmp_path / "data"
        with (
            patch.object(Path, "chmod", side_effect=PermissionError("denied")),
            pytest.raises(PermissionError, match="denied"),
        ):
            secure_mkdir(target)

    def test_windows_skips_chmod(self, tmp_path: Path) -> None:
        # This test works on any platform by mocking sys.platform
        target = tmp_path / "windir"
        with patch("gxassessms.core.security.permissions.sys") as mock_sys:
            mock_sys.platform = "win32"
            with patch.object(Path, "chmod") as mock_chmod:
                secure_mkdir(target)
        assert target.exists()
        mock_chmod.assert_not_called()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
class TestCheckDirectoryPermissions:
    """Tests for check_directory_permissions -- broad-access detection."""

    def test_mode_0o700_not_broad(self, tmp_path: Path) -> None:
        target = tmp_path / "tight"
        target.mkdir(mode=0o700)
        target.chmod(0o700)
        result = check_directory_permissions(target)
        assert result.is_broad_access is False
        assert result.mode_octal == "0o700"
        assert result.warnings == ()

    def test_mode_0o750_is_broad(self, tmp_path: Path) -> None:
        target = tmp_path / "group_rx"
        target.mkdir()
        target.chmod(0o750)
        result = check_directory_permissions(target)
        assert result.is_broad_access is True
        assert result.mode_octal == "0o750"
        assert any("broad" in w for w in result.warnings)

    def test_mode_0o720_is_broad(self, tmp_path: Path) -> None:
        target = tmp_path / "group_w"
        target.mkdir()
        target.chmod(0o720)
        result = check_directory_permissions(target)
        assert result.is_broad_access is True
        assert result.mode_octal == "0o720"
        assert any("broad" in w for w in result.warnings)

    def test_mode_0o701_is_broad(self, tmp_path: Path) -> None:
        target = tmp_path / "world_x"
        target.mkdir()
        target.chmod(0o701)
        result = check_directory_permissions(target)
        assert result.is_broad_access is True
        assert result.mode_octal == "0o701"
        assert any("broad" in w for w in result.warnings)

    def test_mode_0o755_is_broad(self, tmp_path: Path) -> None:
        target = tmp_path / "open"
        target.mkdir()
        target.chmod(0o755)
        result = check_directory_permissions(target)
        assert result.is_broad_access is True
        assert result.mode_octal == "0o755"
        assert any("broad" in w for w in result.warnings)

    def test_nonexistent_path_not_broad(self, tmp_path: Path) -> None:
        target = tmp_path / "does_not_exist"
        result = check_directory_permissions(target)
        assert result.is_broad_access is False
        assert result.mode_octal is None
        assert len(result.warnings) > 0

    def test_stat_permission_error(self, tmp_path: Path) -> None:
        target = tmp_path / "no_access"
        target.mkdir()
        with patch.object(Path, "stat", side_effect=PermissionError("forbidden")):
            result = check_directory_permissions(target)
        assert result.is_broad_access is False
        assert result.mode_octal is None
        assert any("forbidden" in w for w in result.warnings)


class TestWarnBroadPermissions:
    """Tests for warn_broad_permissions -- advisory logging."""

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
    def test_broad_dir_logs_warning(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        target = tmp_path / "broad"
        target.mkdir()
        target.chmod(0o755)
        with caplog.at_level(logging.WARNING):
            result = warn_broad_permissions(target, "test context")
        assert result is True
        assert any(
            "test context" in record.message
            for record in caplog.records
            if record.levelno >= logging.WARNING
        )

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
    def test_restrictive_dir_no_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        target = tmp_path / "tight"
        target.mkdir()
        target.chmod(0o700)
        with caplog.at_level(logging.WARNING):
            result = warn_broad_permissions(target, "secure dir")
        assert result is False
        assert not any(record.levelno >= logging.WARNING for record in caplog.records)

    def test_nonexistent_path_no_crash(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        target = tmp_path / "ghost"
        with caplog.at_level(logging.WARNING):
            result = warn_broad_permissions(target, "missing dir")
        assert result is False
