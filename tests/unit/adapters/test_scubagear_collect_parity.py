"""ScubaGear collect() parity test after build_collection_output refactor."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from gxassessms.adapters.scubagear.adapter import ScubaGearAdapter
from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.domain.enums import ToolSource


def _make_config(output_dir: str) -> EngagementConfig:
    tc = ToolConfig(enabled=True, output_dir=output_dir)
    auth = AuthConfig(method="device_code", tenant_id="t-1", client_id="c-1")
    return EngagementConfig(
        client_name="Test",
        tenant_id="t-1",
        auth=auth,
        tools={"scubagear": tc},
    )


def _make_scuba_results_json() -> dict:
    """Minimal valid ScubaResults JSON structure."""
    return {
        "Results": {
            "AAD": [
                {
                    "Controls": [
                        {
                            "Control ID": "MS.AAD.1.1v1",
                            "Result": "Pass",
                            "Details": "",
                        }
                    ]
                }
            ]
        }
    }


class TestScubaGearCollectParity:
    """Verify that the refactored collect() produces the expected CollectionOutput."""

    def test_collect_returns_expected_output(self, tmp_path: Path) -> None:
        # output_dir starts empty so existing_dirs will be empty
        output_dir = tmp_path / "scubagear_output"
        output_dir.mkdir()

        run_dir = output_dir / "M365BaselineConformance_20260411"
        run_dir.mkdir()
        results_file = run_dir / "ScubaResults.json"
        results_file.write_text(json.dumps(_make_scuba_results_json(), indent=2), encoding="utf-8")

        adapter = ScubaGearAdapter()
        config = _make_config(str(output_dir))

        mock_verification = MagicMock()
        mock_verification.to_json_dict.return_value = {"version": "1.7.1"}

        # Patch iterdir on output_dir to return empty set for existing_dirs snapshot,
        # then let the real run_dir.iterdir() work normally.
        original_iterdir = Path.iterdir
        call_count = [0]

        def mock_iterdir(self_path):
            call_count[0] += 1
            # First call is output_dir.iterdir() for existing_dirs -- return empty
            if call_count[0] == 1:
                return iter([])
            return original_iterdir(self_path)

        with (
            patch("gxassessms.core.security.permissions.secure_mkdir"),
            patch(
                "gxassessms.adapters._base.run_verified_powershell", return_value=mock_verification
            ),
            patch(
                "gxassessms.adapters.scubagear.adapter.find_latest_output_dir", return_value=run_dir
            ),
            patch.object(Path, "iterdir", mock_iterdir),
        ):
            result = adapter.collect(config, auth=None)

        assert result.tool == ToolSource.SCUBAGEAR
        assert result.tool_slug == "scubagear"
        assert len(result.artifacts) == 1
        artifact = result.artifacts[0]
        assert artifact.target_relpath == "scubagear/ScubaResults.json"
        assert artifact.target_relpath.startswith("scubagear/")
        assert len(artifact.sha256) == 64
        assert all(c in "0123456789abcdef" for c in artifact.sha256)
        assert "modules" in result.execution_metadata
        assert "module_provenance" in result.execution_metadata
