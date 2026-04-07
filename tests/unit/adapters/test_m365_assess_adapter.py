"""Unit tests for M365AssessAdapter.collect() validation."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from gxassessms.adapters.m365_assess import M365AssessAdapter
from gxassessms.core.config.config import AuthConfig, EngagementConfig, ToolConfig
from gxassessms.core.contracts.errors import CollectionError


def _make_config(
    output_dir: str = "",
    script_dir: str = "",
    extra_args: list[str] | None = None,
) -> EngagementConfig:
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
                extra_args=extra_args or [],
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


class TestExtraArgsBlocking:
    """collect() must reject extra_args that override adapter-owned parameters."""

    @pytest.mark.parametrize("arg", ["-TenantId:badtenant", "-OutputPath:evil-dir"])
    def test_adapter_owned_param_raises(self, tmp_path: Path, arg: str) -> None:
        adapter = M365AssessAdapter()
        config = _make_config(output_dir=str(tmp_path), script_dir=str(tmp_path), extra_args=[arg])
        with pytest.raises(CollectionError, match="adapter-owned parameters"):
            adapter.collect(config, auth=None)

    def test_safe_extra_arg_passes_block_check(self, tmp_path: Path) -> None:
        """A well-formed, non-blocked arg must not be rejected by the block check."""
        adapter = M365AssessAdapter()
        config = _make_config(
            output_dir=str(tmp_path), script_dir=str(tmp_path), extra_args=["-Verbose"]
        )
        with (
            patch("gxassessms.adapters.m365_assess.adapter.run_powershell"),
            pytest.raises(CollectionError, match="did not produce new CSV output"),
        ):
            # Block check passed; fails later because no CSV output was produced.
            adapter.collect(config, auth=None)


class TestFreshnessCheck:
    """collect() freshness check must detect rewrites via size when mtime is unchanged."""

    def test_same_mtime_different_size_csv_accepted(self, tmp_path: Path) -> None:
        """On coarse-timestamp filesystems a rewritten CSV may not advance mtime.
        The freshness check must fall back to file size so the run is not rejected."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        script_dir = tmp_path / "scripts"
        script_dir.mkdir()

        csv_file = output_dir / "Entra-Security-Config.csv"
        csv_file.write_text("short")
        original_mtime = csv_file.stat().st_mtime

        def _rewrite_same_mtime(*_args: object, **_kwargs: object) -> None:
            csv_file.write_text("longer content after rewrite")
            os.utime(csv_file, (original_mtime, original_mtime))

        adapter = M365AssessAdapter()
        config = _make_config(output_dir=str(output_dir), script_dir=str(script_dir))

        with (
            patch(
                "gxassessms.adapters.m365_assess.adapter.run_powershell",
                side_effect=_rewrite_same_mtime,
            ),
            # Freshness check passed (size changed); fails at controls check, not
            # at "did not produce new CSV output".
            pytest.raises(CollectionError, match="controls metadata missing"),
        ):
            adapter.collect(config, auth=None)
