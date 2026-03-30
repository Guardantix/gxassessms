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
        config_path.write_text(yaml.dump(config_data))
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
