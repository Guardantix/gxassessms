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
        mock_discover.return_value = []
        mock_repo.return_value.create.return_value = "eng-test-001"
        mock_build.return_value.run.return_value = None
        runner = CliRunner()
        result = runner.invoke(cli, ["run", str(config_path)])
        assert result.exit_code == 0
        mock_repo.return_value.create.assert_called_once()
        mock_build.return_value.run.assert_called_once()

    def test_dry_run_shows_config_valid_not_preflight_passed(self, tmp_path: Path) -> None:
        """Dry run should not claim 'Preflight passed' since no prereq checks run."""
        config_path = _write_config(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--dry-run", str(config_path)])
        assert "preflight passed" not in result.output.lower()
        assert "config valid" in result.output.lower() or result.exit_code == 0

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
