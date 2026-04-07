"""Unit tests for gxassessms.reporting.basic_renderer."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from gxassessms.reporting.basic_renderer import BasicDocxRenderer, _find_renderer_path


class TestFindRendererPath:
    def test_prefers_repo_relative_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange: BOTH repo-relative and CWD paths exist — repo-relative must win.
        fake_file = tmp_path / "src" / "gxassessms" / "reporting" / "basic_renderer.py"
        fake_file.parent.mkdir(parents=True)
        fake_file.touch()
        expected = tmp_path / "report-renderers" / "basic"
        expected.mkdir(parents=True)

        # CWD also has a renderer — function must still return the repo-relative one.
        cwd_dir = tmp_path / "cwd_with_renderer"
        cwd_dir.mkdir()
        (cwd_dir / "report-renderers" / "basic").mkdir(parents=True)
        monkeypatch.chdir(cwd_dir)

        # Act
        with patch("gxassessms.reporting.basic_renderer.__file__", str(fake_file)):
            result = _find_renderer_path()

        assert result == expected

    def test_falls_back_to_cwd(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Arrange: fake __file__ where repo-relative path does NOT exist
        fake_file = tmp_path / "nowhere" / "src" / "gxassessms" / "reporting" / "basic_renderer.py"

        # Create renderer only under a separate CWD directory
        cwd_dir = tmp_path / "cwd_base"
        cwd_dir.mkdir()
        cwd_path = cwd_dir / "report-renderers" / "basic"
        cwd_path.mkdir(parents=True)
        monkeypatch.chdir(cwd_dir)

        # Act
        with patch("gxassessms.reporting.basic_renderer.__file__", str(fake_file)):
            result = _find_renderer_path()

        assert result == cwd_path

    def test_raises_file_not_found_when_both_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Arrange: fake __file__ with no renderer anywhere, CWD is an empty dir
        fake_file = tmp_path / "nowhere" / "src" / "gxassessms" / "reporting" / "basic_renderer.py"
        empty_cwd = tmp_path / "empty_cwd"
        empty_cwd.mkdir()
        monkeypatch.chdir(empty_cwd)

        # Act / Assert
        with (
            patch("gxassessms.reporting.basic_renderer.__file__", str(fake_file)),
            pytest.raises(FileNotFoundError) as exc_info,
        ):
            _find_renderer_path()

        msg = str(exc_info.value)
        # Verify the message names both specific computed paths so callers can act on the info.
        # repo_root is tmp_path/"nowhere" (4 parents up from fake_file)
        assert str(tmp_path / "nowhere" / "report-renderers" / "basic") in msg
        assert str(empty_cwd / "report-renderers" / "basic") in msg


class TestBasicDocxRenderer:
    @patch("gxassessms.reporting.basic_renderer.NodeRenderer")
    @patch("gxassessms.reporting.basic_renderer._find_renderer_path")
    def test_init_wires_node_renderer_with_correct_params(
        self,
        mock_find: MagicMock,
        mock_node_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_find.return_value = tmp_path

        renderer = BasicDocxRenderer()

        mock_node_cls.assert_called_once_with(
            package_path=tmp_path,
            format="docx",
            supported_payload_versions=">=1.0.0,<2.0.0",
            name="basic_docx",
        )
        assert renderer._renderer_path == tmp_path

    @patch(
        "gxassessms.reporting.basic_renderer._find_renderer_path",
        side_effect=FileNotFoundError("renderer missing"),
    )
    def test_init_propagates_file_not_found(self, mock_find_path: MagicMock) -> None:
        with pytest.raises(FileNotFoundError, match="renderer missing"):
            BasicDocxRenderer()
        mock_find_path.assert_called_once()

    @patch("gxassessms.reporting.basic_renderer.NodeRenderer")
    @patch("gxassessms.reporting.basic_renderer._find_renderer_path")
    def test_render_delegates_to_node_renderer(
        self,
        mock_find: MagicMock,
        mock_node_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_find.return_value = tmp_path
        mock_node = mock_node_cls.return_value
        expected_output = tmp_path / "out.docx"
        mock_node.render.return_value = expected_output

        renderer = BasicDocxRenderer()
        payload = MagicMock()

        result = renderer.render(payload, tmp_path)

        assert result == expected_output
        mock_node.render.assert_called_once_with(payload, tmp_path)

    @patch("gxassessms.reporting.basic_renderer.NodeRenderer")
    @patch("gxassessms.reporting.basic_renderer._find_renderer_path")
    def test_render_propagates_node_renderer_exception(
        self,
        mock_find: MagicMock,
        mock_node_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        # Fail-closed contract: render() must not swallow exceptions from NodeRenderer.
        mock_find.return_value = tmp_path
        mock_node = mock_node_cls.return_value
        mock_node.render.side_effect = RuntimeError("node process failed")

        renderer = BasicDocxRenderer()
        payload = MagicMock()

        with pytest.raises(RuntimeError, match="node process failed"):
            renderer.render(payload, tmp_path)


class TestBasicDocxRendererEntryPoint:
    def test_class_attributes_match_registered_entry_point(self) -> None:
        """Smoke test: verifies class-level attributes used by the renderer registry."""
        assert BasicDocxRenderer.format == "docx"
        assert BasicDocxRenderer.supported_payload_versions == ">=1.0.0,<2.0.0"
