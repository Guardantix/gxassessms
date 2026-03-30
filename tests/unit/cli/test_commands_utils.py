"""Tests for CLI utility commands (preflight, adapters, analytics) and integration tests.

Split from test_commands.py per file-size guidance: Tasks 3-5 tests live
in test_commands.py; Tasks 6-8 tests live here.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml
from click.testing import CliRunner

from gxassessms.cli.main import cli

# ---------------------------------------------------------------------------
# Preflight and adapters tests
# ---------------------------------------------------------------------------


class TestPreflightCommand:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["preflight", "--help"])
        assert result.exit_code == 0
        assert "config" in result.output.lower() or "validation" in result.output.lower()

    def test_requires_config_argument(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["preflight"])
        assert result.exit_code != 0

    def test_missing_config_file_shows_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["preflight", "/nonexistent/config.yaml"])
        assert result.exit_code != 0

    @patch("gxassessms.cli._helpers.discover_cli_adapters")
    def test_valid_config_shows_pass(self, mock_discover: MagicMock, tmp_path: Path) -> None:
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
            "tools": {"scubagear": True},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        mock_discover.return_value = []

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["preflight", str(config_path)],
            env={"GX_SECRET": "test-value"},  # pragma: allowlist secret
            catch_exceptions=False,
        )
        assert result.exit_code == 0


class TestAdaptersGroup:
    def test_help_shows_subcommands(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["adapters", "--help"])
        assert result.exit_code == 0
        assert "list" in result.output
        assert "check" in result.output
        assert "scaffold" in result.output


class TestAdaptersList:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["adapters", "list", "--help"])
        assert result.exit_code == 0

    @patch("gxassessms.cli._helpers.discover_adapter_metadata")
    def test_no_adapters_shows_message(self, mock_discover: MagicMock) -> None:
        mock_discover.return_value = []
        runner = CliRunner()
        result = runner.invoke(cli, ["adapters", "list"])
        assert result.exit_code == 0


class TestAdaptersCheck:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["adapters", "check", "--help"])
        assert result.exit_code == 0


class TestAdaptersScaffold:
    def test_help_shows_description(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["adapters", "scaffold", "--help"])
        assert result.exit_code == 0

    def test_requires_name_argument(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["adapters", "scaffold"])
        assert result.exit_code != 0


class TestAdaptersCheckBehavior:
    @patch("gxassessms.cli.commands.adapters.discover_cli_adapters", autospec=True)
    def test_adapter_with_prerequisites_pass(self, mock_discover: MagicMock) -> None:
        """Adapter with satisfied prerequisites shows PASS."""
        adapter = MagicMock()
        adapter.tool_name = "scubagear"
        adapter.capabilities = frozenset({"collect", "parse", "prerequisites"})
        adapter.check_prerequisites.return_value = {"satisfied": True, "message": "Found"}
        mock_discover.return_value = [adapter]
        runner = CliRunner()
        result = runner.invoke(cli, ["adapters", "check"])
        assert result.exit_code == 0
        assert "PASS" in result.output

    @patch("gxassessms.cli.commands.adapters.discover_cli_adapters", autospec=True)
    def test_adapter_without_prerequisites_capability_shows_warn(
        self, mock_discover: MagicMock
    ) -> None:
        """Adapter missing 'prerequisites' capability shows WARN."""
        adapter = MagicMock()
        adapter.tool_name = "mytool"
        adapter.capabilities = frozenset({"collect", "parse"})
        mock_discover.return_value = [adapter]
        runner = CliRunner()
        result = runner.invoke(cli, ["adapters", "check"])
        assert result.exit_code == 0
        assert "WARN" in result.output or "warn" in result.output.lower()

    @patch("gxassessms.cli.commands.adapters.discover_cli_adapters", autospec=True)
    def test_adapter_prerequisites_not_satisfied_shows_fail(self, mock_discover: MagicMock) -> None:
        """Adapter with unsatisfied prerequisites shows FAIL."""
        adapter = MagicMock()
        adapter.tool_name = "maester"
        adapter.capabilities = frozenset({"collect", "parse", "prerequisites"})
        adapter.check_prerequisites.return_value = {
            "satisfied": False,
            "message": "Maester not installed",
        }
        mock_discover.return_value = [adapter]
        runner = CliRunner()
        result = runner.invoke(cli, ["adapters", "check"])
        assert result.exit_code == 0
        assert "FAIL" in result.output or "fail" in result.output.lower()

    @patch("gxassessms.cli.commands.adapters.discover_cli_adapters", autospec=True)
    def test_adapter_check_prerequisites_raises_shows_fail(self, mock_discover: MagicMock) -> None:
        """If check_prerequisites() raises RuntimeError, the adapter shows FAIL with the error."""
        adapter = MagicMock()
        adapter.tool_name = "flaky_tool"
        adapter.capabilities = frozenset({"prerequisites"})
        adapter.check_prerequisites.side_effect = RuntimeError("subprocess failed")
        mock_discover.return_value = [adapter]
        runner = CliRunner()
        result = runner.invoke(cli, ["adapters", "check"])
        assert result.exit_code == 0
        assert "FAIL" in result.output or "fail" in result.output.lower()
        assert "subprocess failed" in result.output


class TestAdaptersScaffoldValidation:
    def test_scaffold_rejects_name_starting_with_digit(self, tmp_path: Path) -> None:
        """Scaffold name must start with a letter."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["adapters", "scaffold", "123invalid", "--output-dir", str(tmp_path)]
        )
        assert result.exit_code != 0
        assert "invalid" in result.output.lower() or "name" in result.output.lower()

    def test_scaffold_rejects_name_with_path_separator(self, tmp_path: Path) -> None:
        """Scaffold name must not contain path separators (fails regex validation)."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["adapters", "scaffold", "evil/path", "--output-dir", str(tmp_path)]
        )
        assert result.exit_code != 0

    def test_scaffold_creates_expected_files(self, tmp_path: Path) -> None:
        """Successful scaffold creates adapter.py, parser.py, mappings.py, fixtures/."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["adapters", "scaffold", "mytool", "--output-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        adapter_dir = tmp_path / "mytool"
        assert (adapter_dir / "__init__.py").exists()
        assert (adapter_dir / "adapter.py").exists()
        assert (adapter_dir / "parser.py").exists()
        assert (adapter_dir / "mappings.py").exists()
        assert (adapter_dir / "fixtures").is_dir()
        adapter_content = (adapter_dir / "adapter.py").read_text(encoding="utf-8")
        assert "class MytoolAdapter" in adapter_content
        assert 'tool_name: str = "mytool"' in adapter_content

    def test_scaffold_fails_if_directory_already_exists(self, tmp_path: Path) -> None:
        """Scaffold exits nonzero if the target directory already exists."""
        (tmp_path / "existing_tool").mkdir()
        runner = CliRunner()
        result = runner.invoke(
            cli, ["adapters", "scaffold", "existing_tool", "--output-dir", str(tmp_path)]
        )
        assert result.exit_code != 0
        assert "already exists" in result.output.lower() or "exists" in result.output.lower()


# ---------------------------------------------------------------------------
# Analytics tests (stub)
# ---------------------------------------------------------------------------


class TestAnalyticsGroup:
    def test_help_shows_subcommands(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["analytics", "--help"])
        assert result.exit_code == 0
        assert "tuning" in result.output
        assert "cost" in result.output
        assert "coverage" in result.output


class TestAnalyticsTuning:
    def test_shows_private_package_message(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["analytics", "tuning"])
        assert (
            "gxassessms-guardantix" in result.output
            or "private package" in result.output.lower()
            or "requires" in result.output.lower()
        )


class TestAnalyticsCost:
    def test_shows_private_package_message(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["analytics", "cost"])
        assert (
            "gxassessms-guardantix" in result.output
            or "private package" in result.output.lower()
            or "requires" in result.output.lower()
        )


class TestAnalyticsCoverage:
    def test_shows_private_package_message(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["analytics", "coverage"])
        assert (
            "gxassessms-guardantix" in result.output
            or "private package" in result.output.lower()
            or "requires" in result.output.lower()
        )


# ---------------------------------------------------------------------------
# Integration tests -- verify all commands are registered and accessible
# ---------------------------------------------------------------------------


class TestCLIIntegration:
    """Verify all expected commands are registered on the main CLI group."""

    def test_all_top_level_commands_registered(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0

        expected_commands = [
            "run",
            "collect",
            "consolidate",
            "report",
            "replay",
            "review",
            "engagement",
            "preflight",
            "adapters",
            "analytics",
        ]
        for cmd in expected_commands:
            assert cmd in result.output, f"Command '{cmd}' not in help output"

    def test_engagement_subcommands_registered(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "--help"])
        assert result.exit_code == 0
        for subcmd in ["create", "list", "status", "archive", "restore", "purge", "export"]:
            assert subcmd in result.output, f"Subcommand 'engagement {subcmd}' not in help output"

    def test_adapters_subcommands_registered(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["adapters", "--help"])
        assert result.exit_code == 0
        for subcmd in ["list", "check", "scaffold"]:
            assert subcmd in result.output, f"Subcommand 'adapters {subcmd}' not in help output"

    def test_analytics_subcommands_registered(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["analytics", "--help"])
        assert result.exit_code == 0
        for subcmd in ["tuning", "cost", "coverage"]:
            assert subcmd in result.output, f"Subcommand 'analytics {subcmd}' not in help output"


class TestCLIErrorHandling:
    """Verify consistent error handling across commands."""

    def test_run_bad_config_exit_code(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "/nonexistent.yaml"])
        assert result.exit_code != 0

    def test_collect_bad_config_exit_code(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "/nonexistent.yaml"])
        assert result.exit_code != 0

    def test_consolidate_bad_config_exit_code(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["consolidate", "--engagement-id", "eng-001", "/nonexistent.yaml"]
        )
        assert result.exit_code != 0

    def test_report_bad_config_exit_code(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--engagement-id", "eng-001", "/nonexistent.yaml"])
        assert result.exit_code != 0

    def test_preflight_bad_config_exit_code(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["preflight", "/nonexistent.yaml"])
        assert result.exit_code != 0

    def test_engagement_create_bad_config_exit_code(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "create", "/nonexistent.yaml"])
        assert result.exit_code != 0

    def test_engagement_purge_no_confirm_exit_code(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["engagement", "purge", "eng-001"])
        assert result.exit_code != 0
