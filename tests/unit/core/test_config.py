"""Tests for engagement configuration loading and validation."""

from pathlib import Path

import pytest

from gxassessms.core.config.config import (
    AuthConfig,
    EngagementConfig,
    ToolConfig,
    load_config,
    validate_config,
)
from gxassessms.core.contracts.errors import ConfigError


@pytest.fixture
def fixtures_config_dir() -> Path:
    return Path(__file__).parent / "../../fixtures/configs"


class TestToolConfig:
    def test_defaults(self) -> None:
        tc = ToolConfig(enabled=True)
        assert tc.enabled is True
        assert tc.modules == []
        assert tc.timeout == 600
        assert tc.extra_args == {}


class TestAuthConfig:
    def test_create_client_credential(self) -> None:
        ac = AuthConfig(
            method="client_credential",
            tenant_id="00000000-0000-0000-0000-000000000001",
            client_id="00000000-0000-0000-0000-000000000002",
            client_secret_env="GX_CLIENT_SECRET",
        )
        assert ac.method == "client_credential"
        assert ac.client_secret_env == "GX_CLIENT_SECRET"


class TestEngagementConfig:
    def test_create_minimal(self) -> None:
        cfg = EngagementConfig(
            client_name="Test",
            tenant_id="00000000-0000-0000-0000-000000000001",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="00000000-0000-0000-0000-000000000001",
                client_id="00000000-0000-0000-0000-000000000002",
                client_secret_env="GX_CLIENT_SECRET",
            ),
            tools={},
        )
        assert cfg.client_name == "Test"
        assert cfg.max_parallel == 4


class TestLoadConfig:
    def test_load_minimal_config(self, fixtures_config_dir: Path) -> None:
        cfg = load_config(fixtures_config_dir / "minimal.yaml")
        assert cfg.client_name == "Test Client"
        assert cfg.tenant_id == "00000000-0000-0000-0000-000000000001"
        assert "scubagear" in cfg.tools
        assert cfg.tools["scubagear"].enabled is True

    def test_load_full_config(self, fixtures_config_dir: Path) -> None:
        cfg = load_config(fixtures_config_dir / "full.yaml")
        assert cfg.client_name == "Acme Healthcare"
        assert cfg.max_parallel == 3
        assert cfg.tools["scubagear"].modules == ["aad", "exo", "sharepoint", "teams"]
        assert cfg.tools["scubagear"].timeout == 1200
        assert cfg.tools["monkey365"].enabled is False
        assert cfg.report_formats == ["docx", "pptx"]

    def test_load_nonexistent_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            load_config(tmp_path / "nonexistent.yaml")

    def test_load_invalid_yaml_raises(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text(": : : not valid yaml [[[")
        with pytest.raises(ConfigError):
            load_config(bad_file)


class TestValidateConfig:
    def test_valid_config_no_errors(self, fixtures_config_dir: Path) -> None:
        cfg = load_config(fixtures_config_dir / "minimal.yaml")
        errors, _warnings = validate_config(cfg)
        assert errors == []

    def test_missing_tenant_id_is_error(self) -> None:
        cfg = EngagementConfig(
            client_name="Test",
            tenant_id="",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="",
                client_id="test",
                client_secret_env="GX_SECRET",
            ),
            tools={},
        )
        errors, _warnings = validate_config(cfg)
        assert any("tenant_id" in e for e in errors)

    def test_no_enabled_tools_is_warning(self) -> None:
        cfg = EngagementConfig(
            client_name="Test",
            tenant_id="00000000-0000-0000-0000-000000000001",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="00000000-0000-0000-0000-000000000001",
                client_id="test",
                client_secret_env="GX_SECRET",
            ),
            tools={},
        )
        _errors, warnings = validate_config(cfg)
        assert any("tool" in w.lower() for w in warnings)
