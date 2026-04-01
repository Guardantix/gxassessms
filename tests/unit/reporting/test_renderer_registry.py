"""Tests for renderer registry -- discovery, version validation, Node.js invocation."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from gxassessms.core.contracts.errors import (
    PayloadVersionError,
    RendererDependencyError,
    ReportError,
)
from gxassessms.core.domain.models import ReportPayload
from gxassessms.reporting.renderer_registry import (
    NodeRenderer,
    RendererRegistry,
    check_node_available,
    validate_version_compatibility,
)


def _make_payload(**overrides: Any) -> ReportPayload:
    defaults = {
        "schema_version": "1.0.0",
        "engagement_id": "eng-001",
        "tenant_name": "Test Client",
        "assessment_date": "2026-03-25",
        "tool_sources": ["ScubaGear"],
        "findings": [],
        "coverage": [],
        "narratives": {"executive_summary": None, "roadmap": None, "findings_narrative": None},
        "metadata": {},
    }
    defaults.update(overrides)
    return ReportPayload(**defaults)


# -- Version Validation --------------------------------------------------------


class TestValidateVersionCompatibility:
    def test_compatible_exact_match(self) -> None:
        validate_version_compatibility("1.0.0", ">=1.0.0,<2.0.0")

    def test_compatible_patch_version(self) -> None:
        validate_version_compatibility("1.2.3", ">=1.0.0,<2.0.0")

    def test_incompatible_major_version(self) -> None:
        with pytest.raises(PayloadVersionError, match=r"2\.0\.0"):
            validate_version_compatibility("2.0.0", ">=1.0.0,<2.0.0")

    def test_incompatible_below_range(self) -> None:
        with pytest.raises(PayloadVersionError, match=r"0\.9\.0"):
            validate_version_compatibility("0.9.0", ">=1.0.0,<2.0.0")

    def test_open_upper_bound(self) -> None:
        validate_version_compatibility("99.0.0", ">=1.0.0")

    def test_invalid_payload_version(self) -> None:
        with pytest.raises(PayloadVersionError, match="Invalid"):
            validate_version_compatibility("not.a.version", ">=1.0.0")

    def test_invalid_range_spec(self) -> None:
        with pytest.raises(PayloadVersionError, match="Invalid"):
            validate_version_compatibility("1.0.0", "not a range")


# -- Node.js Availability -----------------------------------------------------


class TestCheckNodeAvailable:
    @patch("gxassessms.reporting.renderer_registry.subprocess.run")
    @patch("gxassessms.reporting.renderer_registry.shutil.which")
    def test_node_available(self, mock_which: MagicMock, mock_run: MagicMock) -> None:
        mock_which.return_value = "/usr/bin/node"
        mock_run.return_value = MagicMock(returncode=0, stdout="v20.0.0\n")
        assert check_node_available() is True

    @patch("gxassessms.reporting.renderer_registry.shutil.which")
    def test_node_not_found(self, mock_which: MagicMock) -> None:
        mock_which.return_value = None
        assert check_node_available() is False

    @patch("gxassessms.reporting.renderer_registry.subprocess.run")
    @patch("gxassessms.reporting.renderer_registry.shutil.which")
    def test_node_non_zero_exit(self, mock_which: MagicMock, mock_run: MagicMock) -> None:
        mock_which.return_value = "/usr/bin/node"
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert check_node_available() is False


# -- NodeRenderer --------------------------------------------------------------


class TestNodeRenderer:
    def test_init_validates_render_js_exists(self, tmp_path: Path) -> None:
        """render.js must exist at init time (fail at discovery, not render)."""
        with pytest.raises(RendererDependencyError, match=r"render\.js"):
            NodeRenderer(
                package_path=tmp_path,
                format="docx",
                supported_payload_versions=">=1.0.0,<2.0.0",
            )

    def test_init_succeeds_with_render_js(self, tmp_path: Path) -> None:
        (tmp_path / "render.js").write_text("// ok")
        renderer = NodeRenderer(
            package_path=tmp_path,
            format="docx",
            supported_payload_versions=">=1.0.0,<2.0.0",
        )
        assert renderer.format == "docx"
        assert renderer.supported_payload_versions == ">=1.0.0,<2.0.0"

    def test_version_check_before_render(self, tmp_path: Path) -> None:
        (tmp_path / "render.js").write_text("// ok")
        renderer = NodeRenderer(
            package_path=tmp_path,
            format="docx",
            supported_payload_versions=">=1.0.0,<2.0.0",
        )
        payload = _make_payload(schema_version="3.0.0")
        with pytest.raises(PayloadVersionError):
            renderer.render(payload, tmp_path / "out")

    @patch("gxassessms.reporting.renderer_registry.check_node_available")
    def test_raises_dependency_error_when_node_missing(
        self, mock_check: MagicMock, tmp_path: Path
    ) -> None:
        (tmp_path / "render.js").write_text("// ok")
        mock_check.return_value = False
        renderer = NodeRenderer(
            package_path=tmp_path,
            format="docx",
            supported_payload_versions=">=1.0.0,<2.0.0",
        )
        payload = _make_payload()
        with pytest.raises(RendererDependencyError, match=r"Node\.js"):
            renderer.render(payload, tmp_path / "out")

    @patch("gxassessms.reporting.renderer_registry.subprocess.run")
    @patch("gxassessms.reporting.renderer_registry.check_node_available")
    @patch("gxassessms.reporting.renderer_registry.write_constants_file")
    def test_successful_render(
        self,
        mock_write_constants: MagicMock,
        mock_check: MagicMock,
        mock_run: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_check.return_value = True

        (tmp_path / "render.js").write_text("// placeholder")
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        expected_output = output_dir / "eng-001_test_renderer.docx"

        # Simulate Node.js creating the output file as a side effect
        def _fake_render(*args: Any, **kwargs: Any) -> MagicMock:
            expected_output.write_bytes(b"fake docx content")
            return MagicMock(returncode=0, stderr="")

        mock_run.side_effect = _fake_render

        renderer = NodeRenderer(
            package_path=tmp_path,
            format="docx",
            supported_payload_versions=">=1.0.0,<2.0.0",
            name="test_renderer",
        )
        payload = _make_payload()
        result = renderer.render(payload, output_dir)
        assert result == expected_output

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert Path(cmd[0]).stem.lower() == "node"
        assert "render.js" in cmd[1]

    @patch("gxassessms.reporting.renderer_registry.subprocess.run")
    @patch("gxassessms.reporting.renderer_registry.check_node_available")
    @patch("gxassessms.reporting.renderer_registry.write_constants_file")
    def test_render_failure_captures_stderr(
        self,
        mock_write_constants: MagicMock,
        mock_check: MagicMock,
        mock_run: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_check.return_value = True
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="Error: Cannot find module 'docx'",
        )

        (tmp_path / "render.js").write_text("// placeholder")

        renderer = NodeRenderer(
            package_path=tmp_path,
            format="docx",
            supported_payload_versions=">=1.0.0,<2.0.0",
        )
        payload = _make_payload()
        with pytest.raises(ReportError, match="Cannot find module"):
            renderer.render(payload, tmp_path / "out")

    @patch("gxassessms.reporting.renderer_registry.subprocess.run")
    @patch("gxassessms.reporting.renderer_registry.check_node_available")
    @patch("gxassessms.reporting.renderer_registry.write_constants_file")
    def test_render_validates_output_file_exists(
        self,
        mock_write_constants: MagicMock,
        mock_check: MagicMock,
        mock_run: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Node.js exits 0 but produces no file -- must raise ReportError."""
        mock_check.return_value = True
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        (tmp_path / "render.js").write_text("// placeholder")
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        # Do NOT create the output file -- simulating a broken renderer

        renderer = NodeRenderer(
            package_path=tmp_path,
            format="docx",
            supported_payload_versions=">=1.0.0,<2.0.0",
        )
        payload = _make_payload()
        with pytest.raises(ReportError, match="did not produce"):
            renderer.render(payload, output_dir)

    def test_custom_timeout(self, tmp_path: Path) -> None:
        (tmp_path / "render.js").write_text("// ok")
        renderer = NodeRenderer(
            package_path=tmp_path,
            format="docx",
            supported_payload_versions=">=1.0.0,<2.0.0",
            timeout_seconds=300,
        )
        assert renderer._timeout_seconds == 300

    @patch("gxassessms.reporting.renderer_registry.subprocess.run")
    @patch("gxassessms.reporting.renderer_registry.check_node_available")
    @patch("gxassessms.reporting.renderer_registry.write_constants_file")
    def test_timeout_raises_report_error(
        self,
        mock_write_constants: MagicMock,
        mock_check: MagicMock,
        mock_run: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Subprocess timeout should be wrapped in ReportError."""
        mock_check.return_value = True
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="node", timeout=120)

        (tmp_path / "render.js").write_text("// placeholder")

        renderer = NodeRenderer(
            package_path=tmp_path,
            format="docx",
            supported_payload_versions=">=1.0.0,<2.0.0",
        )
        payload = _make_payload()
        with pytest.raises(ReportError, match="timed out"):
            renderer.render(payload, tmp_path / "out")


# -- RendererRegistry ----------------------------------------------------------


class TestRendererRegistry:
    def test_register_and_get(self) -> None:
        registry = RendererRegistry()
        mock_renderer = MagicMock()
        mock_renderer.format = "docx"
        registry.register("basic_docx", mock_renderer)
        assert registry.get("basic_docx") is mock_renderer

    def test_get_unknown_returns_none(self) -> None:
        registry = RendererRegistry()
        assert registry.get("nonexistent") is None

    def test_list_renderers(self) -> None:
        registry = RendererRegistry()
        r1 = MagicMock()
        r1.format = "docx"
        r2 = MagicMock()
        r2.format = "pptx"
        registry.register("basic_docx", r1)
        registry.register("gx_pptx", r2)
        names = registry.list_renderers()
        assert "basic_docx" in names
        assert "gx_pptx" in names

    def test_get_by_format(self) -> None:
        registry = RendererRegistry()
        r1 = MagicMock()
        r1.format = "docx"
        r2 = MagicMock()
        r2.format = "pptx"
        registry.register("basic_docx", r1)
        registry.register("gx_pptx", r2)
        docx_renderers = registry.get_by_format("docx")
        assert len(docx_renderers) == 1
        assert docx_renderers[0] is r1

    @patch("gxassessms.reporting.renderer_registry.discover_entry_points")
    def test_discover_from_entry_points(self, mock_discover: MagicMock) -> None:
        mock_renderer_cls = MagicMock()
        mock_instance = MagicMock()
        mock_instance.format = "docx"
        mock_instance.supported_payload_versions = ">=1.0.0,<2.0.0"
        mock_renderer_cls.return_value = mock_instance

        mock_result = MagicMock()
        mock_result.plugins = {"basic_docx": mock_renderer_cls}
        mock_result.errors = []
        mock_discover.return_value = mock_result

        registry = RendererRegistry.discover()
        assert "basic_docx" in registry.list_renderers()

    @patch("gxassessms.reporting.renderer_registry.discover_entry_points")
    def test_discover_captures_errors(self, mock_discover: MagicMock) -> None:
        from gxassessms.registry import DiscoveryError

        mock_result = MagicMock()
        mock_result.plugins = {}
        mock_result.errors = [
            DiscoveryError(
                plugin_name="broken_renderer",
                error_type="ImportError",
                message="No module named 'broken'",
            )
        ]
        mock_discover.return_value = mock_result

        registry = RendererRegistry.discover()
        assert len(registry.list_renderers()) == 0
        assert len(registry.discovery_errors) == 1
