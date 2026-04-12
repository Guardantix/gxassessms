"""Monkey365 collect() parity test after build_collection_output refactor."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from gxassessms.adapters.monkey365.adapter import Monkey365Adapter
from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.domain.enums import ToolSource


def _make_config(output_dir: str) -> EngagementConfig:
    tc = ToolConfig(enabled=True, output_dir=output_dir)
    auth = AuthConfig(method="device_code", tenant_id="t-1", client_id="c-1")
    return EngagementConfig(
        client_name="Test",
        tenant_id="t-1",
        auth=auth,
        tools={"monkey365": tc},
    )


def _make_monkey365_finding() -> dict:
    """Minimal valid Monkey365 OCSF finding."""
    return {
        "findingInfo": {"id": "monkey365-check-1", "title": "Test", "description": "Desc"},
        "severity": "high",
        "statusCode": "fail",
    }


class TestMonkey365CollectParity:
    """Verify that the refactored collect() produces the expected CollectionOutput."""

    def test_collect_returns_expected_output(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "monkey365_output"
        output_dir.mkdir()

        # Pre-existing files snapshot will be empty (no monkey365*.json yet)
        # Then the "new" file appears after the run
        results_file = output_dir / "monkey365-20260411T120000.json"
        results_file.write_text(json.dumps([_make_monkey365_finding()], indent=2), encoding="utf-8")

        mock_verification = MagicMock()
        mock_verification.to_json_dict.return_value = {"module": "monkey365"}

        adapter = Monkey365Adapter()
        config = _make_config(str(output_dir))

        # Track iterdir calls: first call (existing_files snapshot) returns empty,
        # second call (new_files detection) returns the results file
        original_iterdir = Path.iterdir
        call_count = [0]

        def mock_iterdir(self_path):
            call_count[0] += 1
            if call_count[0] == 1:
                return iter([])
            return original_iterdir(self_path)

        with (
            patch("gxassessms.core.security.permissions.secure_mkdir"),
            patch(
                "gxassessms.adapters._base.run_verified_powershell", return_value=mock_verification
            ),
            patch.object(Path, "iterdir", mock_iterdir),
        ):
            result = adapter.collect(config, auth=None)

        assert result.tool == ToolSource.MONKEY365
        assert result.tool_slug == "monkey365"
        assert len(result.artifacts) == 1
        artifact = result.artifacts[0]
        assert artifact.target_relpath.startswith("monkey365/")
        assert artifact.target_relpath == "monkey365/monkey365-20260411T120000.json"
        assert len(artifact.sha256) == 64
        assert all(c in "0123456789abcdef" for c in artifact.sha256)
        assert "module_provenance" in result.execution_metadata
        assert "output_dir" in result.execution_metadata

    def test_collect_multiple_new_files(self, tmp_path: Path) -> None:
        """Multiple new output files are all collected with correct target_relpaths."""
        output_dir = tmp_path / "monkey365_output"
        output_dir.mkdir()

        for name in ("monkey365-a.json", "monkey365-b.json"):
            (output_dir / name).write_text(
                json.dumps([_make_monkey365_finding()], indent=2), encoding="utf-8"
            )

        mock_verification = MagicMock()
        mock_verification.to_json_dict.return_value = {}

        adapter = Monkey365Adapter()
        config = _make_config(str(output_dir))

        original_iterdir = Path.iterdir
        call_count = [0]

        def mock_iterdir(self_path):
            call_count[0] += 1
            if call_count[0] == 1:
                return iter([])
            return original_iterdir(self_path)

        with (
            patch("gxassessms.core.security.permissions.secure_mkdir"),
            patch(
                "gxassessms.adapters._base.run_verified_powershell", return_value=mock_verification
            ),
            patch.object(Path, "iterdir", mock_iterdir),
        ):
            result = adapter.collect(config, auth=None)

        assert len(result.artifacts) == 2
        for artifact in result.artifacts:
            assert artifact.target_relpath.startswith("monkey365/")
            assert len(artifact.sha256) == 64
