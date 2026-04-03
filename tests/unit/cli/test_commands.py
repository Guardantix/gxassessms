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
from gxassessms.pipeline.state import EngagementState


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
    config_path.write_text(yaml.dump(config_data), encoding="utf-8")
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
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_all_plugins", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_run_creates_engagement_and_calls_orchestrator(
        self,
        mock_plugin: MagicMock,
        mock_all_plugins: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_repo.return_value.create.return_value = "eng-test-001"
        mock_build.return_value.run_from.return_value = None
        mock_all_plugins.return_value = []
        mock_plugin.return_value = MagicMock()
        from gxassessms.pipeline.stages import Stage

        mock_build.return_value.determine_resume_stage.return_value = Stage.COLLECT
        mock_build.return_value._get_current_state.return_value = EngagementState.CREATED
        runner = CliRunner()
        result = runner.invoke(cli, ["run", str(config_path)])
        assert result.exit_code == 0
        mock_repo.return_value.create.assert_called_once()
        mock_build.return_value.run_from.assert_called_once()

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
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_all_plugins", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_run_failure_shows_engagement_id_for_retry(
        self,
        mock_plugin: MagicMock,
        mock_all_plugins: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """On pipeline failure, engagement ID should appear in output for recovery."""
        from gxassessms.core.contracts.errors import GxAssessError

        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_repo.return_value.create.return_value = "eng-run-fail-001"
        from gxassessms.pipeline.stages import Stage

        mock_build.return_value.determine_resume_stage.return_value = Stage.COLLECT
        mock_build.return_value._get_current_state.return_value = EngagementState.CREATED
        mock_build.return_value.run_from.side_effect = GxAssessError("network error")
        mock_all_plugins.return_value = []
        mock_plugin.return_value = MagicMock()
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

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_run_missing_enabled_adapter_exits_nonzero(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Enabled tool with no discovered adapter -> exit 1 naming the missing tool."""
        config_path = tmp_path / "config.yaml"
        config_data = {
            "client": {
                "name": "Test",
                "tenant_id": "00000000-0000-0000-0000-000000000001",
            },
            "auth": {
                "method": "client_credential",
                "tenant_id": "00000000-0000-0000-0000-000000000001",
                "client_id": "00000000-0000-0000-0000-000000000002",
                "client_secret_env": "GX_SECRET",  # pragma: allowlist secret
            },
            "tools": {"scubagear": True, "maester": True},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_repo.return_value.create.return_value = "eng-001"
        runner = CliRunner()
        result = runner.invoke(cli, ["run", str(config_path)])
        assert result.exit_code != 0
        assert "maester" in result.output.lower()
        mock_build.return_value.run.assert_not_called()

    def test_force_stage_without_engagement_id_exits_nonzero(self, tmp_path: Path) -> None:
        """--force-stage without --engagement-id -> exit 1 with clear error."""
        config_path = _write_config(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--force-stage", "PARSE", str(config_path)])
        assert result.exit_code != 0
        assert "requires --engagement-id" in result.output

    def test_rerun_without_engagement_id_exits_nonzero(self, tmp_path: Path) -> None:
        """--rerun without --engagement-id -> exit 1 with clear error."""
        config_path = _write_config(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--rerun", str(config_path)])
        assert result.exit_code != 0
        assert "requires --engagement-id" in result.output

    def test_force_stage_normalize_rejected_by_click(self, tmp_path: Path) -> None:
        """NORMALIZE is not a valid --force-stage choice (observations not persisted)."""
        config_path = _write_config(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["run", "--force-stage", "NORMALIZE", "--engagement-id", "eng-1", str(config_path)],
        )
        assert result.exit_code != 0
        # Click reports invalid choice
        assert "invalid" in result.output.lower() or "not one of" in result.output.lower()

    def test_invalid_yaml_config_shows_config_error(self, tmp_path: Path) -> None:
        """File exists but contains invalid YAML structure -> ConfigError exit 1."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text("just a string, not a mapping", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(cli, ["run", str(config_path)])
        assert result.exit_code != 0
        assert "config error" in result.output.lower()

    def test_validation_warnings_printed(self, tmp_path: Path) -> None:
        """Config with no enabled tools prints a validation warning."""
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
            "tools": {},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        # Dry-run to hit the warning path without needing orchestrator mocks
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--dry-run", str(config_path)])
        assert result.exit_code == 0
        assert "warning" in result.output.lower()

    @patch("gxassessms.cli.commands.run.validate_config")
    def test_validation_errors_exit_nonzero(self, mock_validate: MagicMock, tmp_path: Path) -> None:
        """Config with validation errors prints each error and exits 1."""
        config_path = _write_config(tmp_path)
        mock_validate.return_value = (["tenant_id is required"], [])
        runner = CliRunner()
        result = runner.invoke(cli, ["run", str(config_path)])
        assert result.exit_code != 0
        assert "tenant_id" in result.output

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_no_tools_configured_no_adapters_exits_nonzero(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Config with empty tools and no adapters -> exit 1 via no-adapters path."""
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
            "tools": {},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        mock_discover.return_value = []
        mock_repo.return_value.create.return_value = "eng-empty-001"
        runner = CliRunner()
        result = runner.invoke(cli, ["run", str(config_path)])
        assert result.exit_code != 0
        assert "adapter" in result.output.lower()
        assert "just created" in result.output  # newly_created = True path
        mock_build.return_value.run.assert_not_called()

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_no_tools_configured_existing_engagement_no_adapters(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Existing engagement + empty tools + no adapters -> 'Engagement ID' path."""
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
            "tools": {},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        mock_discover.return_value = []
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--engagement-id", "eng-existing", str(config_path)])
        assert result.exit_code != 0
        assert "was created" not in result.output
        assert "eng-existing" in result.output

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_all_plugins", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_rerun_happy_path_calls_reset_and_run(
        self,
        mock_plugin: MagicMock,
        mock_all_plugins: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """--rerun + --engagement-id calls reset_for_rerun then run."""
        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_all_plugins.return_value = []
        mock_plugin.return_value = MagicMock()
        mock_build.return_value.run.return_value = None
        runner = CliRunner()
        result = runner.invoke(
            cli, ["run", "--rerun", "--engagement-id", "eng-rerun", str(config_path)]
        )
        assert result.exit_code == 0
        mock_build.return_value.reset_for_rerun.assert_called_once()
        mock_build.return_value.run.assert_called_once()

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_all_plugins", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_force_stage_happy_path_calls_reset_and_run_from(
        self,
        mock_plugin: MagicMock,
        mock_all_plugins: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """--force-stage + --engagement-id calls reset_for_rerun then run_from."""
        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_all_plugins.return_value = []
        mock_plugin.return_value = MagicMock()
        mock_build.return_value.run_from.return_value = None
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["run", "--force-stage", "PARSE", "--engagement-id", "eng-fs", str(config_path)],
        )
        assert result.exit_code == 0
        mock_build.return_value.reset_for_rerun.assert_called_once()
        mock_build.return_value.run_from.assert_called_once()

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_all_plugins", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_pipeline_gxassess_error_shows_engagement_id(
        self,
        mock_plugin: MagicMock,
        mock_all_plugins: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """GxAssessError during pipeline run prints engagement ID for retry."""
        from gxassessms.core.contracts.errors import GxAssessError

        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_all_plugins.return_value = []
        mock_plugin.return_value = MagicMock()
        from gxassessms.pipeline.stages import Stage

        mock_build.return_value.determine_resume_stage.return_value = Stage.COLLECT
        mock_build.return_value._get_current_state.return_value = EngagementState.CREATED
        mock_build.return_value.run_from.side_effect = GxAssessError("network error")
        mock_repo.return_value.create.return_value = "eng-err-001"
        runner = CliRunner()
        result = runner.invoke(cli, ["run", str(config_path)])
        assert result.exit_code != 0
        assert "eng-err-001" in result.output
        assert "network error" in result.output.lower()

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_all_plugins", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_run_complete_engagement_is_noop(
        self,
        mock_plugin: MagicMock,
        mock_all_plugins: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        tmp_path: Path,
    ) -> None:
        """mseco run --engagement-id on COMPLETE engagement prints message, doesn't run."""
        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_plugin.return_value = MagicMock()
        mock_all_plugins.return_value = []
        mock_build.return_value.determine_resume_stage.return_value = None
        mock_build.return_value._get_current_state.return_value = EngagementState.COMPLETE
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--engagement-id", "eng-done", str(config_path)])
        assert result.exit_code == 0
        assert "complete" in result.output.lower()
        mock_build.return_value.run.assert_not_called()
        mock_build.return_value.run_from.assert_not_called()

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_all_plugins", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_run_qa_review_engagement_prints_approval_message(
        self,
        mock_plugin: MagicMock,
        mock_all_plugins: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        tmp_path: Path,
    ) -> None:
        """mseco run --engagement-id on QA_REVIEW engagement tells user to approve."""
        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_plugin.return_value = MagicMock()
        mock_all_plugins.return_value = []
        mock_build.return_value.determine_resume_stage.return_value = None
        mock_build.return_value._get_current_state.return_value = EngagementState.QA_REVIEW
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--engagement-id", "eng-qa", str(config_path)])
        assert result.exit_code == 0
        assert "qa" in result.output.lower()
        mock_build.return_value.run.assert_not_called()

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_all_plugins", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_run_failed_engagement_resumes_from_failed_stage(
        self,
        mock_plugin: MagicMock,
        mock_all_plugins: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        tmp_path: Path,
    ) -> None:
        """mseco run --engagement-id on FAILED engagement resumes from the failed stage."""
        from gxassessms.pipeline.stages import Stage

        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_plugin.return_value = MagicMock()
        mock_all_plugins.return_value = []
        mock_build.return_value.determine_resume_stage.return_value = Stage.NORMALIZE
        mock_build.return_value._get_current_state.return_value = EngagementState.FAILED
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--engagement-id", "eng-fail", str(config_path)])
        assert result.exit_code == 0
        mock_build.return_value.reset_for_rerun.assert_called_once()
        mock_build.return_value.run_from.assert_called_once()
        call_kwargs = mock_build.return_value.run_from.call_args
        assert call_kwargs[1]["start_stage"] == Stage.NORMALIZE


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
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]  # One adapter matching enabled tools
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
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_repo.return_value.create.return_value = "eng-collect-003"
        mock_build.return_value.run_from.side_effect = GxAssessError("tool timeout")
        runner = CliRunner()
        result = runner.invoke(cli, ["collect", str(config_path)])
        assert result.exit_code != 0
        assert "eng-collect-003" in result.output

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_collect_missing_enabled_adapter_exits_nonzero(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Enabled tool with no discovered adapter -> exit 1 naming the missing tool."""
        config_path = tmp_path / "config.yaml"
        config_data = {
            "client": {
                "name": "Test",
                "tenant_id": "00000000-0000-0000-0000-000000000001",
            },
            "auth": {
                "method": "client_credential",
                "tenant_id": "00000000-0000-0000-0000-000000000001",
                "client_id": "00000000-0000-0000-0000-000000000002",
                "client_secret_env": "GX_SECRET",  # pragma: allowlist secret
            },
            "tools": {"scubagear": True, "maester": True},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_repo.return_value.create.return_value = "eng-collect-missing"
        runner = CliRunner()
        result = runner.invoke(cli, ["collect", str(config_path)])
        assert result.exit_code != 0
        assert "maester" in result.output.lower()
        mock_build.return_value.run_from.assert_not_called()

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_collect_existing_engagement_calls_reset_for_rerun(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """collect --engagement-id should reset state before run_from for retry."""
        from gxassessms.pipeline.stages import Stage

        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_build.return_value.run_from.return_value = None
        runner = CliRunner()
        result = runner.invoke(
            cli, ["collect", "--engagement-id", "eng-retry-001", str(config_path)]
        )
        assert result.exit_code == 0
        mock_build.return_value.reset_for_rerun.assert_called_once_with(
            "eng-retry-001", Stage.COLLECT
        )

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    def test_collect_new_engagement_does_not_call_reset(
        self,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """New engagement (no --engagement-id) should NOT call reset_for_rerun."""
        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_repo.return_value.create.return_value = "eng-new-001"
        mock_build.return_value.run_from.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["collect", str(config_path)])
        assert result.exit_code == 0
        mock_build.return_value.reset_for_rerun.assert_not_called()


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

    def test_requires_engagement_id_option(self, tmp_path: Path) -> None:
        """consolidate requires --engagement-id since it operates on existing data."""
        config_path = _write_config(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["consolidate", str(config_path)])
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
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_consolidate_happy_path_calls_run_from_with_stop_stage(
        self,
        mock_plugin: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        tmp_path: Path,
    ) -> None:
        """consolidate should call run_from with stop_stage=Stage.CONSOLIDATE
        and start_stage=Stage.CONSOLIDATE (default, no --reparse)."""
        from gxassessms.pipeline.stages import Stage

        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_plugin.return_value = MagicMock()
        mock_build.return_value.run_from.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["consolidate", "--engagement-id", "eng-001", str(config_path)])
        assert result.exit_code == 0
        call_kwargs = mock_build.return_value.run_from.call_args
        assert call_kwargs.kwargs.get("stop_stage") == Stage.CONSOLIDATE
        assert call_kwargs.kwargs.get("start_stage") == Stage.CONSOLIDATE

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_consolidate_failure_shows_engagement_id(
        self,
        mock_plugin: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        tmp_path: Path,
    ) -> None:
        from gxassessms.core.contracts.errors import GxAssessError

        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
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
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_consolidate_reparse_uses_parse_start_stage(
        self,
        mock_plugin: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        tmp_path: Path,
    ) -> None:
        """--reparse flag should cause consolidate to start from Stage.PARSE."""
        from gxassessms.pipeline.stages import Stage

        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
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

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_consolidate_calls_reset_for_rerun_before_run_from(
        self,
        mock_plugin: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        tmp_path: Path,
    ) -> None:
        """consolidate must reset state before run_from for terminal-state engagements."""
        from gxassessms.pipeline.stages import Stage

        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_plugin.return_value = MagicMock()
        mock_build.return_value.run_from.return_value = None
        runner = CliRunner()
        result = runner.invoke(
            cli, ["consolidate", "--engagement-id", "eng-cons-reset", str(config_path)]
        )
        assert result.exit_code == 0
        mock_build.return_value.reset_for_rerun.assert_called_once_with(
            "eng-cons-reset", Stage.CONSOLIDATE
        )

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_consolidate_reparse_resets_to_parse_stage(
        self,
        mock_plugin: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        tmp_path: Path,
    ) -> None:
        """--reparse should reset to PARSE stage, not CONSOLIDATE."""
        from gxassessms.pipeline.stages import Stage

        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_plugin.return_value = MagicMock()
        mock_build.return_value.run_from.return_value = None
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["consolidate", "--engagement-id", "eng-cons-reparse", "--reparse", str(config_path)],
        )
        assert result.exit_code == 0
        mock_build.return_value.reset_for_rerun.assert_called_once_with(
            "eng-cons-reparse", Stage.PARSE
        )

    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.filter_and_validate_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    def test_consolidate_missing_enabled_adapter_exits_nonzero(
        self,
        mock_plugin: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_filter: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Enabled tool with no adapter -> exit 1, run_from not called."""
        config_path = _write_config(tmp_path)
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_filter.side_effect = SystemExit(1)
        mock_plugin.return_value = MagicMock()
        runner = CliRunner()
        result = runner.invoke(
            cli, ["consolidate", "--engagement-id", "eng-cons-missing", str(config_path)]
        )
        assert result.exit_code != 0
        mock_build.return_value.run_from.assert_not_called()


class TestReportCommand:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--help"])
        assert result.exit_code == 0

    def test_requires_config_argument(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["report"])
        assert result.exit_code != 0

    def test_requires_engagement_id_option(self, tmp_path: Path) -> None:
        """report requires --engagement-id since it operates on existing findings."""
        config_path = _write_config(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["report", str(config_path)])
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

    def test_from_option_shows_valid_choices_in_help(self) -> None:
        """--from option help text should list the valid stage choices."""
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", "--help"])
        assert result.exit_code == 0
        assert "parse" in result.output.lower()
        assert "consolidate" in result.output.lower()

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    @patch("gxassessms.cli._helpers.discover_all_plugins", autospec=True)
    def test_replay_happy_path_loads_config_from_snapshot(
        self,
        mock_all_plugins: MagicMock,
        mock_plugin: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_artifacts: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """replay should load config from engagement snapshot, not require a config arg."""
        import json

        config_snapshot = {
            "client_name": "Acme Corp",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "auth": {
                "method": "client_credential",
                "tenant_id": "00000000-0000-0000-0000-000000000001",
                "client_id": "00000000-0000-0000-0000-000000000002",
                "client_secret_env": "GX_SECRET",  # pragma: allowlist secret
            },
            "tools": {},
            "max_parallel": 4,
            "report_formats": ["docx"],
            "report_theme": "basic",
            "qa_model": "claude-sonnet-4-6",
            "qa_token_budget": 100000,
        }
        mock_repo.return_value.get.return_value = {
            "engagement_id": "eng-replay-001",
            "config_snapshot": json.dumps(config_snapshot),
        }
        mock_artifacts.return_value.get_engagement_dir.return_value = tmp_path
        mock_discover.return_value = []
        mock_plugin.return_value = None
        mock_all_plugins.return_value = []
        mock_build.return_value.run_from.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", "eng-replay-001"])
        assert result.exit_code == 0
        # run_from should NOT receive config=None
        call_kwargs = mock_build.return_value.run_from.call_args
        assert call_kwargs.kwargs.get("config") is not None

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_replay_engagement_not_found_exits_nonzero(
        self,
        mock_artifacts: MagicMock,
        mock_repo: MagicMock,
    ) -> None:
        """replay should exit nonzero with a clear message when engagement dir not found."""
        import json

        config_snapshot = {
            "client_name": "Test Corp",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "auth": {
                "method": "client_credential",
                "tenant_id": "00000000-0000-0000-0000-000000000001",
                "client_id": "00000000-0000-0000-0000-000000000002",
                "client_secret_env": "GX_SECRET",  # pragma: allowlist secret
            },
            "tools": {},
            "max_parallel": 4,
            "report_formats": ["docx"],
            "report_theme": "basic",
            "qa_model": "claude-sonnet-4-6",
            "qa_token_budget": 100000,
        }
        mock_repo.return_value.get.return_value = {
            "engagement_id": "eng-missing-001",
            "config_snapshot": json.dumps(config_snapshot),
        }
        # Return a path that does not exist on disk
        mock_artifacts.return_value.get_engagement_dir.return_value = Path(
            "/tmp/nonexistent-engagement-dir-xyz"  # noqa: S108
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", "eng-missing-001"])
        assert result.exit_code != 0
        # Should mention missing raw output, not just crash
        assert "raw output" in result.output.lower() or "collection" in result.output.lower()

    def test_from_option_rejects_invalid_stage_name(self) -> None:
        """--from should reject stage names not in (parse, consolidate, qa, report)."""
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", "eng-001", "--from", "badstage"])
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    @patch("gxassessms.cli._helpers.discover_all_plugins", autospec=True)
    def test_replay_calls_reset_for_rerun_before_run_from(
        self,
        mock_all_plugins: MagicMock,
        mock_plugin: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_artifacts: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """replay must call reset_for_rerun before run_from to handle terminal states."""
        import json

        from gxassessms.pipeline.stages import Stage

        config_snapshot = {
            "client_name": "Test Corp",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "auth": {
                "method": "client_credential",
                "tenant_id": "00000000-0000-0000-0000-000000000001",
                "client_id": "00000000-0000-0000-0000-000000000002",
                "client_secret_env": "GX_SECRET",  # pragma: allowlist secret
            },
            "tools": {},
            "max_parallel": 4,
            "report_formats": ["docx"],
            "report_theme": "basic",
            "qa_model": "claude-sonnet-4-6",
            "qa_token_budget": 100000,
        }
        mock_repo.return_value.get.return_value = {
            "engagement_id": "eng-replay-reset-001",
            "config_snapshot": json.dumps(config_snapshot),
        }
        mock_artifacts.return_value.get_engagement_dir.return_value = tmp_path
        mock_discover.return_value = []
        mock_plugin.return_value = None
        mock_all_plugins.return_value = []
        mock_build.return_value.run_from.return_value = None

        runner = CliRunner()
        result = runner.invoke(cli, ["replay", "eng-replay-reset-001"])
        assert result.exit_code == 0
        mock_build.return_value.reset_for_rerun.assert_called_once_with(
            "eng-replay-reset-001", Stage.PARSE
        )

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.build_orchestrator", autospec=True)
    @patch("gxassessms.cli._helpers.discover_cli_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.filter_and_validate_adapters", autospec=True)
    @patch("gxassessms.cli._helpers.build_normalization_policy", autospec=True)
    @patch("gxassessms.cli._helpers.build_consolidation_rule", autospec=True)
    @patch("gxassessms.cli._helpers.discover_plugin", autospec=True)
    @patch("gxassessms.cli._helpers.discover_all_plugins", autospec=True)
    def test_replay_missing_enabled_adapter_exits_nonzero(
        self,
        mock_all_plugins: MagicMock,
        mock_plugin: MagicMock,
        mock_cons_rule: MagicMock,
        mock_norm_policy: MagicMock,
        mock_filter: MagicMock,
        mock_discover: MagicMock,
        mock_build: MagicMock,
        mock_artifacts: MagicMock,
        mock_repo: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Enabled tool with no adapter -> exit 1, run_from not called."""
        import json

        config_snapshot = {
            "client_name": "Test Corp",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "auth": {
                "method": "client_credential",
                "tenant_id": "00000000-0000-0000-0000-000000000001",
                "client_id": "00000000-0000-0000-0000-000000000002",
                "client_secret_env": "GX_SECRET",  # pragma: allowlist secret
            },
            "tools": {"scubagear": True, "maester": True},
            "max_parallel": 4,
            "report_formats": ["docx"],
            "report_theme": "basic",
            "qa_model": "claude-sonnet-4-6",
            "qa_token_budget": 100000,
        }
        mock_repo.return_value.get.return_value = {
            "engagement_id": "eng-replay-missing-001",
            "config_snapshot": json.dumps(config_snapshot),
        }
        mock_artifacts.return_value.get_engagement_dir.return_value = tmp_path
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_discover.return_value = [mock_adapter]
        mock_filter.side_effect = SystemExit(1)

        runner = CliRunner()
        result = runner.invoke(cli, ["replay", "eng-replay-missing-001"])
        assert result.exit_code != 0
        mock_build.return_value.run_from.assert_not_called()


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

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_create_happy_path(self, mock_get: MagicMock, tmp_path: Path) -> None:
        """Successful create loads config, validates, creates engagement."""
        config_path = _write_config(tmp_path)
        mock_get.return_value.create.return_value = "eng-create-001"
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "create", str(config_path)])
        assert result.exit_code == 0
        assert "created" in result.output.lower()
        mock_get.return_value.create.assert_called_once()

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_create_repo_error(self, mock_get: MagicMock, tmp_path: Path) -> None:
        """repo.create raising GxAssessError should exit nonzero."""
        from gxassessms.core.contracts.errors import GxAssessError

        config_path = _write_config(tmp_path)
        mock_get.return_value.create.side_effect = GxAssessError("DB locked")
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "create", str(config_path)])
        assert result.exit_code != 0

    def test_create_invalid_config_shows_config_error(self, tmp_path: Path) -> None:
        """Invalid YAML file -> ConfigError exit 1."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text("not a mapping", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "create", str(config_path)])
        assert result.exit_code != 0
        assert "config error" in result.output.lower()

    @patch("gxassessms.cli.commands.engagement.validate_config")
    def test_create_validation_errors_exit_nonzero(
        self, mock_validate: MagicMock, tmp_path: Path
    ) -> None:
        """Validation errors in create should print errors and exit 1."""
        config_path = _write_config(tmp_path)
        mock_validate.return_value = (["tenant_id is required"], ["No tools warning"])
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "create", str(config_path)])
        assert result.exit_code != 0
        assert "tenant_id" in result.output
        assert "warning" in result.output.lower()


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
        assert "no engagements" in result.output.lower()

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_list_with_engagements(self, mock_get: MagicMock) -> None:
        """List with actual engagements renders a table."""
        mock_get.return_value.list_all.return_value = [
            {
                "engagement_id": "eng-list-001",
                "client_name": "Acme Corp",
                "tenant_id": "tenant-uuid",
                "state": "COMPLETE",
                "created_at": "2026-03-25T10:00:00Z",
            },
            {
                "engagement_id": "eng-list-002",
                "client_name": "Beta Inc",
                "tenant_id": "tenant-uuid-2",
                "state": "CREATED",
                "created_at": "2026-03-26T10:00:00Z",
            },
        ]
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "list"])
        assert result.exit_code == 0
        assert "eng-list-001" in result.output
        assert "eng-list-002" in result.output

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_list_gxassess_error_exits_nonzero(self, mock_get: MagicMock) -> None:
        """GxAssessError during list should exit nonzero."""
        from gxassessms.core.contracts.errors import GxAssessError

        mock_get.return_value.list_all.side_effect = GxAssessError("DB read error")
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "list"])
        assert result.exit_code != 0
        assert "failed" in result.output.lower()


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

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_status_happy_path(self, mock_get: MagicMock) -> None:
        """Status with a valid engagement renders table and exits 0."""
        mock_get.return_value.get.return_value = {
            "engagement_id": "eng-status-001",
            "client_name": "Acme Corp",
            "tenant_id": "tenant-uuid",
            "state": "COMPLETE",
            "created_at": "2026-03-25T10:00:00Z",
        }
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "status", "eng-status-001"])
        assert result.exit_code == 0

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_status_gxassess_error(self, mock_get: MagicMock) -> None:
        """GxAssessError during status should exit nonzero."""
        from gxassessms.core.contracts.errors import GxAssessError

        mock_get.return_value.get.side_effect = GxAssessError("DB error")
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "status", "eng-status-err"])
        assert result.exit_code != 0


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

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_purge_success_shows_audit_path(
        self, mock_artifacts: MagicMock, mock_repo: MagicMock
    ) -> None:
        """Successful purge prints the audit manifest path."""
        mock_artifacts.return_value.purge.return_value = {
            "audit_path": "/data/audits/eng-001-audit.json"
        }
        mock_repo.return_value.delete.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "purge", "eng-001", "--confirm"])
        assert result.exit_code == 0
        assert "/data/audits/eng-001-audit.json" in result.output

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_purge_success_without_audit_path_still_exits_zero(
        self, mock_artifacts: MagicMock, mock_repo: MagicMock
    ) -> None:
        """Successful purge exits 0 even if no audit_path in manifest."""
        mock_artifacts.return_value.purge.return_value = {}
        mock_repo.return_value.delete.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "purge", "eng-001", "--confirm"])
        assert result.exit_code == 0
        assert "purged" in result.output.lower()

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_purge_dir_already_removed(
        self, mock_artifacts: MagicMock, mock_repo: MagicMock, tmp_path: Path
    ) -> None:
        """When engagement dir is already gone, should note it and clean up DB only."""
        # Point to a path that does not exist on disk
        nonexistent = tmp_path / "nonexistent"
        mock_artifacts.return_value.get_engagement_dir.return_value = nonexistent
        mock_repo.return_value.delete.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "purge", "eng-001", "--confirm"])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_purge_engagement_dir_never_created(
        self, mock_artifacts: MagicMock, mock_repo: MagicMock
    ) -> None:
        """Purge should succeed when engagement dir was never created (DB-only cleanup)."""
        from gxassessms.core.contracts.errors import PersistenceError

        mock_artifacts.return_value.get_engagement_dir.side_effect = PersistenceError(
            "Engagement directory not found for: eng-dbonly"
        )
        mock_repo.return_value.delete.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "purge", "eng-dbonly", "--confirm"])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()
        mock_repo.return_value.delete.assert_called_once_with("eng-dbonly")
        mock_artifacts.return_value.purge.assert_not_called()

    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_purge_outer_gxassess_error(self, mock_artifacts: MagicMock) -> None:
        """Outer GxAssessError catch during purge should exit nonzero."""
        from gxassessms.core.contracts.errors import GxAssessError

        mock_artifacts.return_value.get_engagement_dir.side_effect = GxAssessError("storage error")
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "purge", "eng-001", "--confirm"])
        assert result.exit_code != 0


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

    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_archive_happy_path(self, mock_repo: MagicMock, mock_artifacts: MagicMock) -> None:
        """Successful archive prints confirmation and exits 0."""
        mock_repo.return_value.get.return_value = {
            "engagement_id": "eng-archive-001",
            "client_name": "Acme Corp",
            "tenant_id": "tenant-uuid",
            "state": "COMPLETE",
            "created_at": "2026-03-25T10:00:00Z",
        }
        mock_artifacts.return_value.archive.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "archive", "eng-archive-001"])
        assert result.exit_code == 0
        assert "archived" in result.output.lower()

    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_archive_gxassess_error(self, mock_repo: MagicMock, mock_artifacts: MagicMock) -> None:
        """GxAssessError during archive should exit nonzero."""
        from gxassessms.core.contracts.errors import GxAssessError

        mock_repo.return_value.get.return_value = {
            "engagement_id": "eng-archive-err",
            "client_name": "Acme Corp",
            "tenant_id": "tenant-uuid",
            "state": "COMPLETE",
            "created_at": "2026-03-25T10:00:00Z",
        }
        mock_artifacts.return_value.archive.side_effect = GxAssessError("disk full")
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "archive", "eng-archive-err"])
        assert result.exit_code != 0


class TestEngagementRestore:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "restore", "--help"])
        assert result.exit_code == 0

    def test_requires_engagement_id(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "restore"])
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_restore_happy_path(self, mock_artifacts: MagicMock) -> None:
        """Successful restore prints confirmation and exits 0."""
        mock_artifacts.return_value.restore.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "restore", "eng-restore-001"])
        assert result.exit_code == 0
        assert "restored" in result.output.lower()

    @patch("gxassessms.cli._helpers.get_artifact_manager", autospec=True)
    def test_restore_error(self, mock_artifacts: MagicMock) -> None:
        """GxAssessError during restore should exit nonzero."""
        from gxassessms.core.contracts.errors import GxAssessError

        mock_artifacts.return_value.restore.side_effect = GxAssessError("not archived")
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "restore", "eng-restore-err"])
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
        import json as _json

        mock_get.return_value.get.return_value = {
            "engagement_id": "eng-001",
            "client_name": "Acme Corp",
            "tenant_id": "tenant-uuid",
            "state": "COMPLETE",
            "created_at": "2026-03-25T10:00:00Z",
            "config_snapshot": _json.dumps(
                {
                    "tools": {
                        "scubagear": {"enabled": True, "output_dir": "", "modules": []},
                        "maester": {"enabled": False, "output_dir": "", "modules": []},
                    }
                }
            ),
        }
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "export", "eng-001", "--format", "json"])
        assert result.exit_code == 0
        data = _json.loads(result.output)
        assert "schema_version" in data
        assert data["tools"] == ["scubagear"]  # only enabled tool

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_export_empty_tools_when_no_config_snapshot(self, mock_get: MagicMock) -> None:
        """Export produces empty tool list when config_snapshot is missing."""
        mock_get.return_value.get.return_value = {
            "engagement_id": "eng-001",
            "client_name": "Acme Corp",
            "tenant_id": "tenant-uuid",
            "state": "COMPLETE",
            "created_at": "2026-03-25T10:00:00Z",
        }
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "export", "eng-001", "--format", "json"])
        assert result.exit_code == 0
        import json as _json

        data = _json.loads(result.output)
        assert data["tools"] == []

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_export_yaml_format(self, mock_get: MagicMock) -> None:
        """Export with default yaml format produces valid YAML output."""
        import json as _json

        mock_get.return_value.get.return_value = {
            "engagement_id": "eng-yaml-001",
            "client_name": "Acme Corp",
            "tenant_id": "tenant-uuid",
            "state": "COMPLETE",
            "created_at": "2026-03-25T10:00:00Z",
            "config_snapshot": _json.dumps(
                {
                    "tools": {
                        "scubagear": {"enabled": True, "output_dir": "", "modules": []},
                    }
                }
            ),
        }
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "export", "eng-yaml-001"])
        assert result.exit_code == 0
        data = yaml.safe_load(result.output)
        assert data["engagement_id"] == "eng-yaml-001"
        assert data["tools"] == ["scubagear"]

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_export_gxassess_error(self, mock_get: MagicMock) -> None:
        """GxAssessError during export should exit nonzero."""
        from gxassessms.core.contracts.errors import GxAssessError

        mock_get.return_value.get.side_effect = GxAssessError("DB error")
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "export", "eng-export-err"])
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.get_engagement_repo", autospec=True)
    def test_export_config_snapshot_as_dict(self, mock_get: MagicMock) -> None:
        """config_snapshot already a dict (not JSON string) still extracts tools."""
        mock_get.return_value.get.return_value = {
            "engagement_id": "eng-dict",
            "client_name": "Dict Corp",
            "tenant_id": "tenant-uuid",
            "state": "COMPLETE",
            "created_at": "2026-03-25T10:00:00Z",
            "config_snapshot": {
                "tools": {
                    "scubagear": {"enabled": True, "output_dir": "", "modules": []},
                }
            },
        }
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "export", "eng-dict", "--format", "json"])
        assert result.exit_code == 0
        import json as _json

        data = _json.loads(result.output)
        assert data["tools"] == ["scubagear"]
