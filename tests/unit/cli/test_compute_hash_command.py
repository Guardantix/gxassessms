"""Tests for compute-module-hash CLI command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from gxassessms.cli.main import cli

FAKE_HASH = "sha256tree:v1:" + "a" * 64


class TestComputeModuleHashCommand:
    @patch("gxassessms.adapters._tree_hash.compute_tree_hash", autospec=True)
    @patch("gxassessms.cli.commands.compute_hash.console")
    def test_success_exits_zero_and_prints_expected_output(
        self, mock_console: MagicMock, mock_compute: MagicMock, tmp_path: Path
    ) -> None:
        mod_dir = tmp_path / "MyModule"
        mod_dir.mkdir()
        manifest = mod_dir / "MyModule.psd1"
        manifest.write_text("@{ ModuleVersion = '1.0.0' }", encoding="utf-8")
        mock_compute.return_value = FAKE_HASH

        runner = CliRunner()
        result = runner.invoke(cli, ["compute-module-hash", "--manifest-path", str(manifest)])

        assert result.exit_code == 0
        all_printed = "\n".join(
            " ".join(map(str, c.args)) for c in mock_console.print.call_args_list if c.args
        )
        assert "Module:" in all_printed
        assert "MyModule" in all_printed
        assert "Path:" in all_printed
        assert str(mod_dir) in all_printed
        assert FAKE_HASH in all_printed
        assert "Add to adapter policy.py" in all_printed
        assert f'"{FAKE_HASH}",' in all_printed  # verify hash embedded in snippet with quotes+comma
        mock_compute.assert_called_once_with(mod_dir)

    @patch("gxassessms.cli.commands.compute_hash.console")
    def test_rejects_non_psd1_extension(self, mock_console: MagicMock, tmp_path: Path) -> None:
        bad_file = tmp_path / "not_manifest.txt"
        bad_file.write_text("x", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(cli, ["compute-module-hash", "--manifest-path", str(bad_file)])

        assert result.exit_code == 1
        all_printed = "\n".join(
            " ".join(map(str, c.args)) for c in mock_console.print.call_args_list if c.args
        )
        assert "Expected a .psd1 file" in all_printed
        assert "not_manifest.txt" in all_printed  # command includes the bad filename in the message

    @patch("gxassessms.adapters._tree_hash.compute_tree_hash", autospec=True)
    @patch("gxassessms.cli.commands.compute_hash.console")
    def test_accepts_uppercase_psd1_extension(
        self, mock_console: MagicMock, mock_compute: MagicMock, tmp_path: Path
    ) -> None:
        mod_dir = tmp_path / "M"
        mod_dir.mkdir()
        manifest = mod_dir / "M.PSD1"
        manifest.write_text("@{}", encoding="utf-8")
        mock_compute.return_value = FAKE_HASH

        runner = CliRunner()
        result = runner.invoke(cli, ["compute-module-hash", "--manifest-path", str(manifest)])

        assert result.exit_code == 0
        mock_compute.assert_called_once_with(mod_dir)

    @patch("gxassessms.adapters._tree_hash.compute_tree_hash", autospec=True)
    @patch("gxassessms.cli.commands.compute_hash.console")
    def test_value_error_from_tree_hash_is_reported(
        self, mock_console: MagicMock, mock_compute: MagicMock, tmp_path: Path
    ) -> None:
        mod_dir = tmp_path / "M"
        mod_dir.mkdir()
        manifest = mod_dir / "M.psd1"
        manifest.write_text("@{}", encoding="utf-8")
        mock_compute.side_effect = ValueError("Symlink/junction detected in tree: link.txt")

        runner = CliRunner()
        result = runner.invoke(cli, ["compute-module-hash", "--manifest-path", str(manifest)])

        assert result.exit_code == 1
        all_printed = "\n".join(
            " ".join(map(str, c.args)) for c in mock_console.print.call_args_list if c.args
        )
        assert "Error:" in all_printed
        assert "Symlink/junction detected" in all_printed  # exc message propagated verbatim

    @patch("gxassessms.adapters._tree_hash.compute_tree_hash", autospec=True)
    @patch("gxassessms.cli.commands.compute_hash.console")
    def test_oserror_from_tree_hash_has_cannot_read_prefix(
        self, mock_console: MagicMock, mock_compute: MagicMock, tmp_path: Path
    ) -> None:
        mod_dir = tmp_path / "M"
        mod_dir.mkdir()
        manifest = mod_dir / "M.psd1"
        manifest.write_text("@{}", encoding="utf-8")
        mock_compute.side_effect = OSError("permission denied")

        runner = CliRunner()
        result = runner.invoke(cli, ["compute-module-hash", "--manifest-path", str(manifest)])

        assert result.exit_code == 1
        all_printed = "\n".join(
            " ".join(map(str, c.args)) for c in mock_console.print.call_args_list if c.args
        )
        assert "Cannot read module:" in all_printed
        assert "permission denied" in all_printed  # OSError string follows the prefix

    def test_manifest_path_is_required(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["compute-module-hash"])

        assert result.exit_code == 2
        assert "--manifest-path" in result.output

    def test_manifest_path_must_exist(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.psd1"

        runner = CliRunner()
        result = runner.invoke(cli, ["compute-module-hash", "--manifest-path", str(missing)])

        assert result.exit_code == 2
        assert "--manifest-path" in result.output

    def test_manifest_path_cannot_be_directory(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["compute-module-hash", "--manifest-path", str(tmp_path)])

        assert result.exit_code == 2
        assert "--manifest-path" in result.output
