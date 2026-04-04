"""Tests for engagement lifecycle guardrails -- operator resolution and permission checks."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from gxassessms.cli.commands.engagement import _check_storage_permissions, _resolve_operator
from gxassessms.persistence.artifacts import ArtifactManager


class TestResolveOperator:
    def test_returns_username(self) -> None:
        result = _resolve_operator()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_fallback_on_oserror(self) -> None:
        with patch(
            "getpass.getuser",
            side_effect=OSError("no tty"),
        ):
            assert _resolve_operator() == "unknown"

    def test_fallback_on_keyerror(self) -> None:
        with patch(
            "getpass.getuser",
            side_effect=KeyError("no user"),
        ):
            assert _resolve_operator() == "unknown"


class TestCheckStoragePermissions:
    def test_no_crash_on_missing_engagement(self, tmp_path: Path) -> None:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        artifacts = ArtifactManager(engagements_root=engagements_root)
        # Should not raise -- advisory only
        _check_storage_permissions(artifacts, "nonexistent-id")

    def test_calls_warn_broad_on_existing_dir(self, tmp_path: Path) -> None:
        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        artifacts = ArtifactManager(engagements_root=engagements_root)
        eng_dir = artifacts.create_engagement_dir("eng-test", "Test")
        with patch("gxassessms.core.security.permissions.warn_broad_permissions") as mock_warn:
            _check_storage_permissions(artifacts, "eng-test")
        mock_warn.assert_called_once()
        call_args = mock_warn.call_args
        assert call_args[0][0] == eng_dir
        assert "eng-test" in call_args[0][1]


class TestCLIOperatorPassthrough:
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_archive_passes_operator(self, mock_repo: MagicMock, mock_artifacts: MagicMock) -> None:
        from click.testing import CliRunner

        from gxassessms.cli.main import cli

        mock_repo.return_value.get.return_value = {
            "engagement_id": "eng-001",
            "client_name": "Test",
            "tenant_id": "t",
            "state": "COMPLETE",
            "created_at": "2026-01-01T00:00:00Z",
        }
        mock_artifacts.return_value.archive.return_value = None
        runner = CliRunner()
        runner.invoke(cli, ["engagement", "archive", "eng-001"])
        mock_artifacts.return_value.archive.assert_called_once()
        _, kwargs = mock_artifacts.return_value.archive.call_args
        assert "operator" in kwargs
        assert isinstance(kwargs["operator"], str)
        assert len(kwargs["operator"]) > 0

    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_restore_passes_operator(self, mock_artifacts: MagicMock) -> None:
        from click.testing import CliRunner

        from gxassessms.cli.main import cli

        mock_artifacts.return_value.restore.return_value = None
        runner = CliRunner()
        runner.invoke(cli, ["engagement", "restore", "eng-001"])
        mock_artifacts.return_value.restore.assert_called_once()
        _, kwargs = mock_artifacts.return_value.restore.call_args
        assert "operator" in kwargs

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_purge_passes_operator(self, mock_artifacts: MagicMock, mock_repo: MagicMock) -> None:
        from click.testing import CliRunner

        from gxassessms.cli.main import cli

        mock_artifacts.return_value.purge.return_value = {}
        mock_repo.return_value.delete.return_value = None
        runner = CliRunner()
        runner.invoke(cli, ["engagement", "purge", "eng-001", "--confirm"])
        mock_artifacts.return_value.purge.assert_called_once()
        _, kwargs = mock_artifacts.return_value.purge.call_args
        assert "operator" in kwargs
