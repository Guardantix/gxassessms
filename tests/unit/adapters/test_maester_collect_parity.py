"""Maester collect() parity test after build_collection_output refactor."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from gxassessms.adapters.maester.adapter import MaesterAdapter
from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.domain.enums import ToolSource


def _make_config(output_dir: str) -> EngagementConfig:
    tc = ToolConfig(enabled=True, output_dir=output_dir)
    auth = AuthConfig(method="device_code", tenant_id="t-1", client_id="c-1")
    return EngagementConfig(
        client_name="Test",
        tenant_id="t-1",
        auth=auth,
        tools={"maester": tc},
    )


def _make_maester_results_json() -> dict:
    """Minimal valid Maester TestResults JSON structure."""
    return {
        "Tests": [
            {
                "Id": "EIDSCA.AP01",
                "Result": "Pass",
                "Name": "Test name",
            }
        ]
    }


class TestMaesterCollectParity:
    """Verify that the refactored collect() produces the expected CollectionOutput."""

    def test_collect_returns_expected_output(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "maester_output"
        output_dir.mkdir()

        mock_verification = MagicMock()
        mock_verification.to_json_dict.return_value = {"module": "Maester"}

        # Track run_dir creation so we can plant a results file
        created_run_dirs: list[Path] = []

        def real_secure_mkdir(path, **kwargs):
            path = Path(path) if not isinstance(path, Path) else path
            path.mkdir(parents=True, exist_ok=True)
            if "run-" in path.name:
                created_run_dirs.append(path)
                results_file = path / "TestResults-20260411T120000.json"
                results_file.write_text(
                    json.dumps(_make_maester_results_json(), indent=2), encoding="utf-8"
                )

        adapter = MaesterAdapter()
        config = _make_config(str(output_dir))

        with (
            patch(
                "gxassessms.core.security.permissions.secure_mkdir",
                side_effect=real_secure_mkdir,
            ),
            patch(
                "gxassessms.adapters._base.run_verified_powershell",
                return_value=mock_verification,
            ),
        ):
            result = adapter.collect(config, auth=None)

        assert result.tool == ToolSource.MAESTER
        assert result.tool_slug == "maester"
        assert len(result.artifacts) == 1
        artifact = result.artifacts[0]
        assert artifact.target_relpath.startswith("maester/")
        assert "TestResults" in artifact.target_relpath
        assert len(artifact.sha256) == 64
        assert all(c in "0123456789abcdef" for c in artifact.sha256)
        assert "module_provenance" in result.execution_metadata
