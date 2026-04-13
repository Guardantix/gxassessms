"""M365-Assess collect() parity test after build_collection_output refactor."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from gxassessms.adapters.m365_assess.adapter import M365AssessAdapter
from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.domain.enums import ToolSource

_CSV_HEADER = "Category,Setting,CurrentValue,RecommendedValue,Status,CheckId,Remediation"
_CSV_ROW = "Identity,MFA,Enabled,Enabled,Pass,MS.AAD.1.1v1,No action"

_RISK_SEVERITY = {"MS.AAD": "HIGH"}
_REGISTRY = {"MS.AAD.1.1v1": {"title": "MFA Required", "description": "Enforce MFA"}}


def _make_config(output_dir: str, script_dir: str, controls_dir: str = "") -> EngagementConfig:
    return EngagementConfig(
        client_name="Test Client",
        tenant_id="00000000-0000-0000-0000-000000000001",
        auth=AuthConfig(
            method="client_credential",
            tenant_id="00000000-0000-0000-0000-000000000001",
            client_id="00000000-0000-0000-0000-000000000002",
            client_secret_env="GX_TEST_SECRET",  # pragma: allowlist secret
        ),
        tools={
            "m365_assess": ToolConfig(
                enabled=True,
                output_dir=output_dir,
                script_dir=script_dir,
                controls_dir=controls_dir,
            )
        },
    )


class TestM365AssessCollectParity:
    """Verify that the refactored collect() produces the expected CollectionOutput."""

    def test_collect_returns_expected_output(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "m365_output"
        output_dir.mkdir()
        script_dir = tmp_path / "scripts"
        script_dir.mkdir()
        controls_dir = tmp_path / "controls"
        controls_dir.mkdir()

        # Plant controls files
        (controls_dir / "risk-severity.json").write_text(
            json.dumps(_RISK_SEVERITY), encoding="utf-8"
        )
        (controls_dir / "registry.json").write_text(json.dumps(_REGISTRY), encoding="utf-8")

        adapter = M365AssessAdapter()
        config = _make_config(
            output_dir=str(output_dir),
            script_dir=str(script_dir),
            controls_dir=str(controls_dir),
        )

        def _write_csv(*_args, **_kwargs):
            """Simulate M365-Assess producing a CSV during the PowerShell run."""
            csv_file = output_dir / "Entra-Security-Config.csv"
            csv_file.write_text(f"{_CSV_HEADER}\n{_CSV_ROW}\n", encoding="utf-8")

        with patch(
            "gxassessms.adapters.m365_assess.adapter.run_powershell",
            side_effect=_write_csv,
        ):
            result = adapter.collect(config, auth=None)

        assert result.tool == ToolSource.M365_ASSESS
        assert result.tool_slug == "m365-assess"

        # Should have 1 CSV + 2 controls files = 3 artifacts
        assert len(result.artifacts) == 3

        relpaths = {a.target_relpath for a in result.artifacts}
        assert "m365-assess/Entra-Security-Config.csv" in relpaths
        assert "m365-assess/controls/risk-severity.json" in relpaths
        assert "m365-assess/controls/registry.json" in relpaths

        for artifact in result.artifacts:
            assert artifact.target_relpath.startswith("m365-assess/")
            assert len(artifact.sha256) == 64
            assert all(c in "0123456789abcdef" for c in artifact.sha256)

        assert "script_path" in result.execution_metadata
        assert "tenant_id" in result.execution_metadata
        assert "controls_dir" in result.execution_metadata

    def test_collect_multiple_csv_files(self, tmp_path: Path) -> None:
        """Multiple CSV files are all collected with correct target_relpaths."""
        output_dir = tmp_path / "m365_output"
        output_dir.mkdir()
        script_dir = tmp_path / "scripts"
        script_dir.mkdir()
        controls_dir = tmp_path / "controls"
        controls_dir.mkdir()

        (controls_dir / "risk-severity.json").write_text(
            json.dumps(_RISK_SEVERITY), encoding="utf-8"
        )
        (controls_dir / "registry.json").write_text(json.dumps(_REGISTRY), encoding="utf-8")

        def _write_csvs(*_args, **_kwargs):
            """Simulate M365-Assess producing CSVs during the PowerShell run."""
            for name in ("Entra-Security-Config.csv", "Exchange-Security-Config.csv"):
                (output_dir / name).write_text(f"{_CSV_HEADER}\n{_CSV_ROW}\n", encoding="utf-8")

        adapter = M365AssessAdapter()
        config = _make_config(
            output_dir=str(output_dir),
            script_dir=str(script_dir),
            controls_dir=str(controls_dir),
        )

        with patch(
            "gxassessms.adapters.m365_assess.adapter.run_powershell",
            side_effect=_write_csvs,
        ):
            result = adapter.collect(config, auth=None)

        # 2 CSVs + 2 controls = 4 artifacts
        assert len(result.artifacts) == 4

        csv_artifacts = [a for a in result.artifacts if "/controls/" not in a.target_relpath]
        assert len(csv_artifacts) == 2
        for artifact in csv_artifacts:
            assert artifact.target_relpath.startswith("m365-assess/")
            assert len(artifact.sha256) == 64
