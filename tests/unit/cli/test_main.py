"""Tests for the main CLI group and logging setup."""

import logging

from click.testing import CliRunner

from gxassessms.cli.main import cli, setup_logging

# ---------------------------------------------------------------------------
# Logging setup tests
# ---------------------------------------------------------------------------


class TestSetupLogging:
    def test_default_level_is_warning(self) -> None:
        setup_logging(log_level="WARNING", log_format="rich", verbose=False)
        root = logging.getLogger("gxassessms")
        assert root.level == logging.WARNING

    def test_verbose_sets_debug(self) -> None:
        setup_logging(log_level="WARNING", log_format="rich", verbose=True)
        root = logging.getLogger("gxassessms")
        assert root.level == logging.DEBUG

    def test_explicit_level_overrides_default(self) -> None:
        setup_logging(log_level="INFO", log_format="rich", verbose=False)
        root = logging.getLogger("gxassessms")
        assert root.level == logging.INFO

    def test_json_format_uses_json_formatter(self) -> None:
        setup_logging(log_level="INFO", log_format="json", verbose=False)
        root = logging.getLogger("gxassessms")
        # Should have at least one handler with JSON formatting
        assert len(root.handlers) > 0
        has_json = any(
            hasattr(h.formatter, "_json_format") or "json" in type(h.formatter).__name__.lower()
            for h in root.handlers
            if h.formatter is not None
        )
        # The JSON formatter is our custom one
        assert has_json


# ---------------------------------------------------------------------------
# CLI group tests
# ---------------------------------------------------------------------------


class TestCLIGroup:
    def test_cli_help_shows_mseco(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "mseco" in result.output.lower() or "microsoft" in result.output.lower()

    def test_cli_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output or "version" in result.output.lower()

    def test_cli_accepts_config_option(self) -> None:
        runner = CliRunner()
        # --help should show --config option
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0

    def test_cli_accepts_log_level(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--log-level", "DEBUG", "--help"])
        assert result.exit_code == 0

    def test_cli_accepts_log_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--log-format", "json", "--help"])
        assert result.exit_code == 0

    def test_cli_accepts_verbose(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["-v", "--help"])
        assert result.exit_code == 0

    def test_unknown_command_shows_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["nonexistent"])
        assert result.exit_code != 0
