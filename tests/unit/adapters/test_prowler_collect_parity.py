"""Prowler collect() parity test after build_collection_output refactor."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from gxassessms.adapters.prowler.adapter import ProwlerAdapter
from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.domain.enums import ToolSource

_TEST_SECRET_ENV = "PROWLER_TEST_SECRET"  # pragma: allowlist secret
_TEST_SECRET_VAL = "test-value"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _inject_sp_env_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the test secret env var so --sp-env-auth can proceed."""
    monkeypatch.setenv(_TEST_SECRET_ENV, _TEST_SECRET_VAL)


def _make_config(output_dir: str) -> EngagementConfig:
    tc = ToolConfig(enabled=True, output_dir=output_dir)
    auth = AuthConfig(
        method="client_credential",
        tenant_id="00000000-0000-0000-0000-000000000001",
        client_id="00000000-0000-0000-0000-000000000002",
        client_secret_env=_TEST_SECRET_ENV,
    )
    return EngagementConfig(
        client_name="Test",
        tenant_id="00000000-0000-0000-0000-000000000001",
        subscription_id="12345678-1234-1234-1234-123456789012",
        auth=auth,
        tools={"prowler": tc},
    )


def _make_ocsf_finding() -> dict:
    """Minimal valid Prowler OCSF finding."""
    return {
        "finding_info": {"uid": "abc123", "title": "Test finding"},
        "status_code": "PASS",
        "metadata": {"event_code": "azure_check_1"},
    }


class TestProwlerCollectParity:
    """Verify that the refactored collect() produces the expected CollectionOutput."""

    def test_collect_returns_expected_output(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "prowler_output"
        output_dir.mkdir()

        # Create the OCSF output file that Prowler would produce
        ocsf_file = output_dir / "ProwlerResults.ocsf.json"
        ocsf_file.write_text(json.dumps([_make_ocsf_finding()], indent=2), encoding="utf-8")

        adapter = ProwlerAdapter()
        config = _make_config(str(output_dir))

        mock_result = MagicMock(spec=subprocess.CompletedProcess)
        mock_result.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/prowler"),
            patch("gxassessms.core.security.permissions.secure_mkdir"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = adapter.collect(config, None)

        assert result.tool == ToolSource.PROWLER
        assert result.tool_slug == "prowler"
        assert len(result.artifacts) == 1
        artifact = result.artifacts[0]
        assert artifact.target_relpath.startswith("prowler/")
        assert artifact.target_relpath == "prowler/ProwlerResults.ocsf.json"
        assert len(artifact.sha256) == 64
        assert all(c in "0123456789abcdef" for c in artifact.sha256)
        assert "output_dir" in result.execution_metadata
        assert "auth_method" in result.execution_metadata
        assert "checks" in result.execution_metadata

    def test_collect_multiple_ocsf_files_sorted(self, tmp_path: Path) -> None:
        """Multiple OCSF files result in artifacts sorted by target_relpath."""
        output_dir = tmp_path / "prowler_output"
        output_dir.mkdir()

        for name in ("beta.ocsf.json", "alpha.ocsf.json"):
            (output_dir / name).write_text(
                json.dumps([_make_ocsf_finding()], indent=2), encoding="utf-8"
            )

        adapter = ProwlerAdapter()
        config = _make_config(str(output_dir))

        mock_result = MagicMock(spec=subprocess.CompletedProcess)
        mock_result.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/prowler"),
            patch("gxassessms.core.security.permissions.secure_mkdir"),
            patch("subprocess.run", return_value=mock_result),
            patch.object(
                type(output_dir),
                "rglob",
                return_value=[output_dir / "beta.ocsf.json", output_dir / "alpha.ocsf.json"],
            ),
        ):
            result = adapter.collect(config, None)

        assert len(result.artifacts) == 2
        # build_collection_output sorts by target_relpath
        assert result.artifacts[0].target_relpath < result.artifacts[1].target_relpath
