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

    @patch("gxassessms.cli.commands.preflight._try_ps_adapter_preflight", return_value=None)
    @patch("gxassessms.cli._helpers.discover_cli_adapters")
    def test_mixed_case_tool_name_still_matches(
        self, mock_discover: MagicMock, mock_ps: MagicMock, tmp_path: Path
    ) -> None:
        """Adapter with lowercase tool_name matches mixed-case config key."""
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
            "tools": {"ScubaGear": True},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_adapter.capabilities = frozenset({"prerequisites"})
        mock_adapter.check_prerequisites.return_value = {"satisfied": True, "message": "OK"}
        mock_discover.return_value = [mock_adapter]
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["preflight", str(config_path)],
            env={"GX_SECRET": "test-value"},  # pragma: allowlist secret
            catch_exceptions=False,
        )
        # Should NOT report missing adapter -- case normalization makes them match
        assert "no adapter" not in result.output.lower()
        assert result.exit_code == 0

    @patch("gxassessms.cli.commands.preflight._try_ps_adapter_preflight", return_value=None)
    @patch("gxassessms.cli._helpers.discover_cli_adapters")
    def test_valid_config_shows_pass(
        self, mock_discover: MagicMock, mock_ps: MagicMock, tmp_path: Path
    ) -> None:
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
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_adapter.capabilities = frozenset({"prerequisites"})
        mock_adapter.check_prerequisites.return_value = {"satisfied": True, "message": "OK"}
        mock_discover.return_value = [mock_adapter]

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["preflight", str(config_path)],
            env={"GX_SECRET": "test-value"},  # pragma: allowlist secret
            catch_exceptions=False,
        )
        assert result.exit_code == 0

    @patch("gxassessms.cli.commands.preflight._try_ps_adapter_preflight", return_value=None)
    @patch("gxassessms.cli.commands.preflight.validate_config")
    @patch("gxassessms.cli._helpers.discover_cli_adapters")
    def test_config_validation_errors_show_fail(
        self, mock_discover: MagicMock, mock_validate: MagicMock, mock_ps: MagicMock, tmp_path: Path
    ) -> None:
        """Config validation errors produce FAIL results and exit nonzero."""
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
            "tools": {"scubagear": True},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        mock_validate.return_value = (["tenant_id is required"], [])
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_adapter.capabilities = frozenset({"prerequisites"})
        mock_adapter.check_prerequisites.return_value = {"satisfied": True, "message": "OK"}
        mock_discover.return_value = [mock_adapter]

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["preflight", str(config_path)],
            env={"GX_SECRET": "test-value"},  # pragma: allowlist secret
        )
        assert "FAIL" in result.output
        assert "tenant_id" in result.output
        assert result.exit_code == 1

    @patch("gxassessms.cli._helpers.discover_cli_adapters")
    def test_no_tools_enabled_shows_warning(self, mock_discover: MagicMock, tmp_path: Path) -> None:
        """Config with no enabled tools produces a validation warning."""
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
            "tools": {},
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
        assert "WARN" in result.output
        assert "No tools" in result.output or "no tools" in result.output.lower()

    @patch("gxassessms.cli.commands.preflight._try_ps_adapter_preflight", return_value=None)
    @patch("gxassessms.cli._helpers.discover_cli_adapters")
    def test_adapter_not_in_enabled_tools_skipped(
        self, mock_discover: MagicMock, mock_ps: MagicMock, tmp_path: Path
    ) -> None:
        """Adapter whose tool_name doesn't match any enabled tool is skipped."""
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
            "tools": {"scubagear": True},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        # Adapter that matches the enabled tool
        matching_adapter = MagicMock()
        matching_adapter.tool_name = "scubagear"
        matching_adapter.capabilities = frozenset({"prerequisites"})
        matching_adapter.check_prerequisites.return_value = {
            "satisfied": True,
            "message": "OK",
        }
        # Adapter that does NOT match any enabled tool -- should be skipped
        extra_adapter = MagicMock()
        extra_adapter.tool_name = "maester"
        extra_adapter.capabilities = frozenset({"prerequisites"})
        mock_discover.return_value = [matching_adapter, extra_adapter]

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["preflight", str(config_path)],
            env={"GX_SECRET": "test-value"},  # pragma: allowlist secret
            catch_exceptions=False,
        )
        # "maester" adapter should not appear in output -- it was skipped
        assert "maester" not in result.output.lower()
        # The matching adapter's check_prerequisites was called
        matching_adapter.check_prerequisites.assert_called_once()
        # The skipped adapter's check_prerequisites was NOT called
        extra_adapter.check_prerequisites.assert_not_called()
        assert result.exit_code == 0

    @patch("gxassessms.cli._helpers.discover_cli_adapters")
    def test_adapter_without_prerequisites_via_preflight(
        self, mock_discover: MagicMock, tmp_path: Path
    ) -> None:
        """Adapter missing 'prerequisites' capability shows WARN in preflight."""
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
            "tools": {"scubagear": True},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_adapter.capabilities = frozenset({"collect", "parse"})  # no "prerequisites"
        mock_discover.return_value = [mock_adapter]

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["preflight", str(config_path)],
            env={"GX_SECRET": "test-value"},  # pragma: allowlist secret
            catch_exceptions=False,
        )
        assert "WARN" in result.output
        assert "does not declare prerequisites" in result.output.lower()

    @patch("gxassessms.cli.commands.preflight._try_ps_adapter_preflight", return_value=None)
    @patch("gxassessms.cli._helpers.discover_cli_adapters")
    def test_adapter_prerequisites_not_satisfied_via_preflight(
        self, mock_discover: MagicMock, mock_ps: MagicMock, tmp_path: Path
    ) -> None:
        """Adapter with unsatisfied prerequisites shows FAIL in preflight."""
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
            "tools": {"scubagear": True},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_adapter.capabilities = frozenset({"prerequisites"})
        mock_adapter.check_prerequisites.return_value = {
            "satisfied": False,
            "message": "ScubaGear not installed",
        }
        mock_discover.return_value = [mock_adapter]

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["preflight", str(config_path)],
            env={"GX_SECRET": "test-value"},  # pragma: allowlist secret
        )
        assert "FAIL" in result.output
        assert "ScubaGear not installed" in result.output
        assert result.exit_code == 1

    @patch("gxassessms.cli._helpers.discover_cli_adapters")
    def test_missing_adapter_via_preflight(self, mock_discover: MagicMock, tmp_path: Path) -> None:
        """Enabled tool with no discovered adapter shows FAIL."""
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
            "tools": {"scubagear": True},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        mock_discover.return_value = []  # No adapters discovered

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["preflight", str(config_path)],
            env={"GX_SECRET": "test-value"},  # pragma: allowlist secret
        )
        assert "FAIL" in result.output
        assert "no adapter" in result.output.lower()
        assert result.exit_code == 1

    @patch("gxassessms.cli.commands.preflight._try_ps_adapter_preflight", return_value=None)
    @patch("gxassessms.cli._helpers.discover_cli_adapters")
    def test_auth_env_var_not_set(
        self, mock_discover: MagicMock, mock_ps: MagicMock, tmp_path: Path
    ) -> None:
        """Missing auth env var shows FAIL and exit nonzero."""
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
            "tools": {"scubagear": True},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_adapter.capabilities = frozenset({"prerequisites"})
        mock_adapter.check_prerequisites.return_value = {"satisfied": True, "message": "OK"}
        mock_discover.return_value = [mock_adapter]

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["preflight", str(config_path)],
            env={"GX_SECRET": ""},  # pragma: allowlist secret
        )
        assert "FAIL" in result.output
        assert "GX_SECRET" in result.output
        assert result.exit_code == 1

    def test_config_error_in_preflight(self, tmp_path: Path) -> None:
        """Invalid YAML triggers ConfigError and exits nonzero."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text('not: valid: yaml: [["', encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(cli, ["preflight", str(config_path)])
        assert "config error" in result.output.lower() or "invalid yaml" in result.output.lower()
        assert result.exit_code == 1

    @patch("gxassessms.cli.commands.preflight._try_ps_adapter_preflight", return_value=None)
    @patch("shutil.which", return_value=None)
    @patch("gxassessms.cli._helpers.discover_cli_adapters")
    def test_node_not_found_shows_warning(
        self, mock_discover: MagicMock, mock_which: MagicMock, mock_ps: MagicMock, tmp_path: Path
    ) -> None:
        """Node.js not found produces WARN for renderer dependency."""
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
            "tools": {"scubagear": True},
        }
        config_path.write_text(yaml.dump(config_data), encoding="utf-8")
        mock_adapter = MagicMock()
        mock_adapter.tool_name = "scubagear"
        mock_adapter.capabilities = frozenset({"prerequisites"})
        mock_adapter.check_prerequisites.return_value = {"satisfied": True, "message": "OK"}
        mock_discover.return_value = [mock_adapter]

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["preflight", str(config_path)],
            env={"GX_SECRET": "test-value"},  # pragma: allowlist secret
        )
        assert "WARN" in result.output
        assert "Node.js not found" in result.output


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
    @patch("gxassessms.cli.commands.adapters._try_ps_adapter_baseline_check", return_value=None)
    @patch("gxassessms.cli.commands.adapters.discover_cli_adapters", autospec=True)
    def test_adapter_with_prerequisites_pass(
        self, mock_discover: MagicMock, mock_ps: MagicMock
    ) -> None:
        """Non-PS adapter with satisfied prerequisites shows PASS."""
        adapter = MagicMock()
        adapter.tool_name = "sometool"
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

    @patch("gxassessms.cli.commands.adapters._try_ps_adapter_baseline_check", return_value=None)
    @patch("gxassessms.cli.commands.adapters.discover_cli_adapters", autospec=True)
    def test_adapter_prerequisites_not_satisfied_shows_fail(
        self, mock_discover: MagicMock, mock_ps: MagicMock
    ) -> None:
        """Non-PS adapter with unsatisfied prerequisites shows FAIL."""
        adapter = MagicMock()
        adapter.tool_name = "sometool"
        adapter.capabilities = frozenset({"collect", "parse", "prerequisites"})
        adapter.check_prerequisites.return_value = {
            "satisfied": False,
            "message": "Tool not installed",
        }
        mock_discover.return_value = [adapter]
        runner = CliRunner()
        result = runner.invoke(cli, ["adapters", "check"])
        assert result.exit_code == 0
        assert "FAIL" in result.output or "fail" in result.output.lower()

    @patch("gxassessms.cli.commands.adapters._try_ps_adapter_baseline_check", return_value=None)
    @patch("gxassessms.cli.commands.adapters.discover_cli_adapters", autospec=True)
    def test_adapter_check_prerequisites_raises_shows_fail(
        self, mock_discover: MagicMock, mock_ps: MagicMock
    ) -> None:
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

    @patch("gxassessms.cli.commands.adapters.discover_cli_adapters", autospec=True)
    def test_ps_adapter_calls_verifier_directly(self, mock_discover: MagicMock) -> None:
        """PS adapters go through _try_ps_adapter_baseline_check, not check_prerequisites."""
        adapter = MagicMock()
        adapter.tool_name = "scubagear"
        adapter.capabilities = frozenset({"collect", "parse", "prerequisites"})
        mock_discover.return_value = [adapter]

        mock_pass_result = {
            "check": "scubagear",
            "status": "PASS",
            "message": "ScubaGear 1.5.2 verified (hash_only)",
        }
        with patch(
            "gxassessms.cli.commands.adapters._try_ps_adapter_baseline_check",
            return_value=mock_pass_result,
        ):
            runner = CliRunner()
            result = runner.invoke(cli, ["adapters", "check"])

        assert result.exit_code == 0
        assert "PASS" in result.output
        # check_prerequisites should NOT have been called for PS adapters
        adapter.check_prerequisites.assert_not_called()


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
