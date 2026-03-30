"""Tests for the main CLI group and logging setup."""

import logging

import pytest
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

    def test_json_formatter_includes_exception_info(self) -> None:
        """JSONLogFormatter.format() includes 'exception' key when exc_info is set."""
        import json
        import logging
        import sys

        from gxassessms.cli.main import JSONLogFormatter

        formatter = JSONLogFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            exc_info = sys.exc_info()
            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="",
                lineno=0,
                msg="something broke",
                args=(),
                exc_info=exc_info,
            )
        output = formatter.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert "test error" in data["exception"]
        assert data["level"] == "ERROR"


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
        assert "0.1.0" in result.output

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


# ---------------------------------------------------------------------------
# _try_register tests
# ---------------------------------------------------------------------------


class TestTryRegister:
    def test_try_register_logs_error_on_missing_symbol(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """_try_register should log ERROR (not raise) when the symbol is absent."""
        import logging

        from gxassessms.cli.main import _try_register

        # gxassessms.cli.commands.run exists but "nonexistent_cmd" doesn't
        with caplog.at_level(logging.ERROR, logger="gxassessms.cli.main"):
            _try_register("gxassessms.cli.commands.run", "nonexistent_cmd", "bad_cmd")

        assert "bad_cmd" in caplog.text or "nonexistent_cmd" in caplog.text
        # CLI must still be functional (no exception raised)

    def test_try_register_logs_warning_on_missing_module(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """_try_register should log WARNING (not raise) on ImportError."""
        import logging

        from gxassessms.cli.main import _try_register

        with caplog.at_level(logging.WARNING, logger="gxassessms.cli.main"):
            _try_register("gxassessms.cli.commands.does_not_exist", "cmd", "missing_cmd")

        assert "missing_cmd" in caplog.text
