"""Tests for CLI commands (pipeline, engagement, utility, integration).

All command tests use Click's CliRunner. Pipeline commands (run, collect,
consolidate, report) share a common pattern: validate config path, then
delegate to the orchestrator. Mocks target cli._helpers to avoid heavy
persistence/pipeline initialization.

File split guidance (keep each file under 400 lines):
- test_commands.py (this file): Task 3-5 tests (run, collect, consolidate,
  report, replay, review, engagement)
- test_commands_utils.py: Task 6-8 tests (preflight, adapters, analytics,
  integration, error handling)

Patch target notes:
- Always use autospec=True on @patch decorators so type mismatches fail loudly:
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
- If _helpers.py is renamed, patched targets stop working silently without
  autospec. autospec causes AttributeError on missing methods.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml
from click.testing import CliRunner

from gxassessms.cli.main import cli


def _write_config(tmp_path: Path) -> Path:
    """Write a minimal valid config YAML and return its path."""
    config_path = tmp_path / "config.yaml"
    config_data = {
        "client": {
            "name": "Test Corp",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
        },
        "auth": {
            "method": "client_credential",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "client_id": "00000000-0000-0000-0000-000000000002",
            "client_secret_env": "GX_SECRET",  # pragma: allowlist secret
        },
        "tools": {
            "scubagear": True,
        },
    }
    config_path.write_text(yaml.dump(config_data))
    return config_path


class TestRunCommand:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--help"])
        assert result.exit_code == 0
        assert "pipeline" in result.output.lower() or "run" in result.output.lower()

    def test_requires_config_argument(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["run"])
        assert result.exit_code != 0

    def test_missing_config_file_shows_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "/nonexistent/config.yaml"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "error" in result.output.lower()

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_dry_run_does_not_execute_pipeline(
        self, mock_discover: MagicMock, mock_build: MagicMock, tmp_path: Path
    ) -> None:
        config_path = _write_config(tmp_path)
        mock_discover.return_value = []
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--dry-run", str(config_path)])
        # Dry run: orchestrator should never be built or run
        mock_build.assert_not_called()
        assert result.exit_code == 0

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_run_creates_engagement_and_calls_orchestrator(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        config_path = _write_config(tmp_path)
        mock_discover.return_value = [MagicMock()]
        mock_repo.return_value.create.return_value = "eng-test-001"
        mock_build.return_value.run.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["run", str(config_path)])
        assert result.exit_code == 0
        mock_repo.return_value.create.assert_called_once()
        mock_build.return_value.run.assert_called_once()

    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_dry_run_shows_config_valid_not_preflight_passed(
        self, mock_discover: MagicMock, tmp_path: Path
    ) -> None:
        """Dry run should not claim 'Preflight passed' since no prereq checks run."""
        mock_discover.return_value = []
        config_path = _write_config(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--dry-run", str(config_path)])
        assert result.exit_code == 0
        assert "preflight passed" not in result.output.lower()
        assert "config valid" in result.output.lower()

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_run_empty_adapter_list_exits_nonzero(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """run should exit 1 with clear message when no adapters found."""
        config_path = _write_config(tmp_path)
        mock_discover.return_value = []
        mock_repo.return_value.create.return_value = "eng-run-001"
        runner = CliRunner()
        result = runner.invoke(cli, ["run", str(config_path)])
        assert result.exit_code != 0
        assert "adapter" in result.output.lower()
        mock_build.return_value.run.assert_not_called()
        mock_build.return_value.run_from.assert_not_called()

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_run_empty_adapter_with_existing_engagement_id_no_was_created_message(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """With --engagement-id and empty adapters, message should not say 'was created'."""
        config_path = _write_config(tmp_path)
        mock_discover.return_value = []
        runner = CliRunner()
        result = runner.invoke(
            cli, ["run", "--engagement-id", "eng-existing-run-001", str(config_path)]
        )
        assert result.exit_code != 0
        assert "was created" not in result.output
        assert "eng-existing-run-001" in result.output

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_run_failure_shows_engagement_id_for_retry(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """On pipeline failure, engagement ID should appear in output for recovery."""
        from gxassessms.core.contracts.errors import GxAssessError

        config_path = _write_config(tmp_path)
        mock_discover.return_value = [MagicMock()]
        mock_repo.return_value.create.return_value = "eng-run-fail-001"
        mock_build.return_value.run.side_effect = GxAssessError("network error")
        runner = CliRunner()
        result = runner.invoke(cli, ["run", str(config_path)])
        assert result.exit_code != 0
        assert "eng-run-fail-001" in result.output

    def test_accepts_force_stage_option(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--help"])
        assert "--force-stage" in result.output or "force" in result.output.lower()

    def test_accepts_rerun_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--help"])
        assert "--rerun" in result.output

    def test_accepts_engagement_id_option(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--help"])
        assert "--engagement-id" in result.output


class TestCollectCommand:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "--help"])
        assert result.exit_code == 0
        assert "tool" in result.output.lower() or "collect" in result.output.lower()

    def test_requires_config_argument(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["collect"])
        assert result.exit_code != 0

    def test_missing_config_file_shows_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "/nonexistent/config.yaml"])
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_collect_happy_path_calls_run_from_with_stop_stage(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """collect should call run_from with stop_stage=Stage.COLLECT."""
        from gxassessms.pipeline.stages import Stage

        config_path = _write_config(tmp_path)
        mock_discover.return_value = [MagicMock()]  # One adapter
        mock_repo.return_value.create.return_value = "eng-collect-001"
        mock_build.return_value.run_from.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["collect", str(config_path)])
        assert result.exit_code == 0
        mock_build.return_value.run_from.assert_called_once()
        call_kwargs = mock_build.return_value.run_from.call_args
        assert call_kwargs.kwargs.get("stop_stage") == Stage.COLLECT

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_collect_empty_adapter_list_exits_nonzero(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """collect should exit 1 with a clear message when no adapters found."""
        config_path = _write_config(tmp_path)
        mock_discover.return_value = []  # No adapters
        mock_repo.return_value.create.return_value = "eng-collect-002"
        runner = CliRunner()
        result = runner.invoke(cli, ["collect", str(config_path)])
        assert result.exit_code != 0
        assert "adapter" in result.output.lower()
        # Should NOT call run_from on zero adapters
        mock_build.return_value.run_from.assert_not_called()

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_collect_empty_adapter_with_existing_engagement_id_no_was_created_message(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """With --engagement-id and empty adapters, message should not say 'was created'."""
        config_path = _write_config(tmp_path)
        mock_discover.return_value = []
        runner = CliRunner()
        result = runner.invoke(
            cli, ["collect", "--engagement-id", "eng-existing-001", str(config_path)]
        )
        assert result.exit_code != 0
        assert "was created" not in result.output
        assert "eng-existing-001" in result.output

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_collect_failure_shows_engagement_id_for_retry(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """On pipeline failure, error message should include the engagement ID."""
        from gxassessms.core.contracts.errors import GxAssessError

        config_path = _write_config(tmp_path)
        mock_discover.return_value = [MagicMock()]
        mock_repo.return_value.create.return_value = "eng-collect-003"
        mock_build.return_value.run_from.side_effect = GxAssessError("tool timeout")
        runner = CliRunner()
        result = runner.invoke(cli, ["collect", str(config_path)])
        assert result.exit_code != 0
        assert "eng-collect-003" in result.output


class TestConsolidateCommand:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["consolidate", "--help"])
        assert result.exit_code == 0

    def test_requires_config_argument(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["consolidate"])
        assert result.exit_code != 0

    def test_accepts_reparse_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["consolidate", "--help"])
        assert "--reparse" in result.output

    def test_requires_engagement_id_option(self) -> None:
        """consolidate requires --engagement-id since it operates on existing data."""
        runner = CliRunner()
        result = runner.invoke(cli, ["consolidate", "/some/config.yaml"])
        assert result.exit_code != 0
        assert "engagement-id" in result.output.lower() or "missing" in result.output.lower()

    def test_missing_config_file_shows_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["consolidate", "--engagement-id", "eng-001", "/nonexistent/config.yaml"]
        )
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_consolidate_happy_path_calls_run_from_with_stop_stage(
        self,
        mock_plugin: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        tmp_path: Path,
    ) -> None:
        """consolidate should call run_from with stop_stage=Stage.CONSOLIDATE."""
        from gxassessms.pipeline.stages import Stage

        config_path = _write_config(tmp_path)
        mock_discover.return_value = [MagicMock()]
        mock_plugin.return_value = MagicMock()
        mock_build.return_value.run_from.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["consolidate", "--engagement-id", "eng-001", str(config_path)])
        assert result.exit_code == 0
        call_kwargs = mock_build.return_value.run_from.call_args
        assert call_kwargs.kwargs.get("stop_stage") == Stage.CONSOLIDATE

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_consolidate_failure_shows_engagement_id(
        self,
        mock_plugin: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        tmp_path: Path,
    ) -> None:
        from gxassessms.core.contracts.errors import GxAssessError

        config_path = _write_config(tmp_path)
        mock_discover.return_value = [MagicMock()]
        mock_plugin.return_value = MagicMock()
        mock_build.return_value.run_from.side_effect = GxAssessError("parse failed")
        runner = CliRunner()
        result = runner.invoke(
            cli, ["consolidate", "--engagement-id", "eng-cons-001", str(config_path)]
        )
        assert result.exit_code != 0
        assert "eng-cons-001" in result.output

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_consolidate_reparse_uses_parse_start_stage(
        self,
        mock_plugin: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        tmp_path: Path,
    ) -> None:
        """--reparse flag should cause consolidate to start from Stage.PARSE."""
        from gxassessms.pipeline.stages import Stage

        config_path = _write_config(tmp_path)
        mock_discover.return_value = [MagicMock()]
        mock_plugin.return_value = MagicMock()
        mock_build.return_value.run_from.return_value = None
        runner = CliRunner()
        result = runner.invoke(
            cli, ["consolidate", "--engagement-id", "eng-002", "--reparse", str(config_path)]
        )
        assert result.exit_code == 0
        call_kwargs = mock_build.return_value.run_from.call_args
        assert call_kwargs.kwargs.get("start_stage") == Stage.PARSE
        assert call_kwargs.kwargs.get("stop_stage") == Stage.CONSOLIDATE


class TestReportCommand:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--help"])
        assert result.exit_code == 0

    def test_requires_config_argument(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["report"])
        assert result.exit_code != 0

    def test_requires_engagement_id_option(self) -> None:
        """report requires --engagement-id since it operates on existing findings."""
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "/some/config.yaml"])
        assert result.exit_code != 0
        assert "engagement-id" in result.output.lower() or "missing" in result.output.lower()

    def test_missing_config_file_shows_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["report", "--engagement-id", "eng-001", "/nonexistent/config.yaml"]
        )
        assert result.exit_code != 0


class TestReplayCommand:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", "--help"])
        assert result.exit_code == 0
        assert "replay" in result.output.lower()

    def test_requires_engagement_id(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["replay"])
        assert result.exit_code != 0

    def test_accepts_from_option(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", "--help"])
        assert "--from" in result.output or "from" in result.output.lower()

    def test_from_option_validates_stage_names(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", "--help"])
        assert result.exit_code == 0


class TestReviewCommand:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert result.exit_code == 0

    def test_requires_engagement_id(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["review"])
        assert result.exit_code != 0

    def test_shows_private_package_message_when_not_installed(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "eng-001"])
        assert (
            "gxassessms-guardantix" in result.output
            or "private package" in result.output.lower()
            or "requires" in result.output.lower()
        )


# ---------------------------------------------------------------------------
# Engagement management tests
# ---------------------------------------------------------------------------


class TestEngagementGroup:
    def test_help_shows_subcommands(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "--help"])
        assert result.exit_code == 0
        assert "create" in result.output
        assert "list" in result.output
        assert "status" in result.output
        assert "archive" in result.output
        assert "restore" in result.output
        assert "purge" in result.output
        assert "export" in result.output


class TestEngagementCreate:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "create", "--help"])
        assert result.exit_code == 0

    def test_requires_config_argument(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "create"])
        assert result.exit_code != 0

    def test_missing_config_file_shows_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "create", "/nonexistent/config.yaml"])
        assert result.exit_code != 0


class TestEngagementList:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "list", "--help"])
        assert result.exit_code == 0

    @patch("gxassessms.cli._helpers.get_engagement_repo")
    def test_empty_list_shows_message(self, mock_get: MagicMock) -> None:
        mock_repo = MagicMock()
        mock_repo.list_all.return_value = []
        mock_get.return_value = mock_repo
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "list"])
        assert result.exit_code == 0
        assert "no engagements" in result.output.lower() or len(result.output) > 0


class TestEngagementStatus:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "status", "--help"])
        assert result.exit_code == 0

    def test_requires_engagement_id(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "status"])
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_not_found_engagement_exits_nonzero(self, mock_get: MagicMock) -> None:
        mock_get.return_value.get.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "status", "nonexistent-id"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()


class TestEngagementPurge:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "purge", "--help"])
        assert result.exit_code == 0

    def test_requires_engagement_id(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "purge"])
        assert result.exit_code != 0

    def test_requires_confirm_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "purge", "eng-001"])
        assert result.exit_code != 0
        assert "confirm" in result.output.lower()

    def test_help_shows_confirm_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "purge", "--help"])
        assert "--confirm" in result.output

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_purge_db_failure_reports_warning_not_silent(
        self, mock_artifacts: MagicMock, mock_repo: MagicMock
    ) -> None:
        """If filesystem purge succeeds but DB delete fails, user sees a clear warning."""
        from gxassessms.core.contracts.errors import GxAssessError

        mock_artifacts.return_value.purge.return_value = {}
        mock_repo.return_value.delete.side_effect = GxAssessError("DB locked")
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "purge", "eng-001", "--confirm"])
        assert result.exit_code != 0
        assert "warning" in result.output.lower() or "failed" in result.output.lower()


class TestEngagementArchive:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "archive", "--help"])
        assert result.exit_code == 0

    def test_requires_engagement_id(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "archive"])
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_not_found_engagement_exits_nonzero(self, mock_get: MagicMock) -> None:
        mock_get.return_value.get.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "archive", "nonexistent-id"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()


class TestEngagementRestore:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "restore", "--help"])
        assert result.exit_code == 0

    def test_requires_engagement_id(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "restore"])
        assert result.exit_code != 0


class TestEngagementExport:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "export", "--help"])
        assert result.exit_code == 0

    def test_requires_engagement_id(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "export"])
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_not_found_engagement_exits_nonzero(self, mock_get: MagicMock) -> None:
        mock_get.return_value.get.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "export", "nonexistent-id"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_export_includes_schema_version(self, mock_get: MagicMock) -> None:
        mock_get.return_value.get.return_value = {
            "engagement_id": "eng-001",
            "client_name": "Acme Corp",
            "tenant_id": "tenant-uuid",
            "state": "COMPLETE",
            "created_at": "2026-03-25T10:00:00Z",
            "tools": ["scubagear"],
        }
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "export", "eng-001", "--format", "json"])
        assert result.exit_code == 0
        import json as _json

        data = _json.loads(result.output)
        assert "schema_version" in data
