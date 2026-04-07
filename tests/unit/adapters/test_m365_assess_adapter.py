"""Unit tests for M365AssessAdapter.collect() validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from gxassessms.adapters.m365_assess import M365AssessAdapter
from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.contracts.errors import CollectionError


def _make_config(output_dir: str = "", script_dir: str = "") -> EngagementConfig:
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
            )
        },
    )


class TestCollectValidation:
    """collect() should fail fast with clear errors on missing required config."""

    def test_missing_output_dir_raises(self) -> None:
        adapter = M365AssessAdapter()
        config = _make_config(output_dir="", script_dir="/some/path")
        with pytest.raises(CollectionError, match="output_dir"):
            adapter.collect(config, auth=None)

    def test_missing_script_dir_raises(self, tmp_path: Path) -> None:
        adapter = M365AssessAdapter()
        config = _make_config(output_dir=str(tmp_path), script_dir="")
        with pytest.raises(CollectionError, match="script_dir"):
            adapter.collect(config, auth=None)
