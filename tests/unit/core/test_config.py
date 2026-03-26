"""Tests for engagement configuration loading and validation."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from gxassessms.core.config.config import (
    AuthConfig,
    EngagementConfig,
    ToolConfig,
    load_config,
    validate_config,
)
from gxassessms.core.contracts.errors import ConfigError, ConfigValidationError


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

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            ToolConfig(enabled=True, enbaled=True)  # type: ignore[call-arg]


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

    def test_rejects_invalid_method(self) -> None:
        with pytest.raises(ValidationError):
            AuthConfig(
                method="invalid",  # type: ignore[arg-type]
                tenant_id="t1",
                client_id="c1",
            )


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

    def test_frozen_config_rejects_mutation(self) -> None:
        cfg = EngagementConfig(
            client_name="Test",
            tenant_id="00000000-0000-0000-0000-000000000001",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="00000000-0000-0000-0000-000000000001",
                client_id="00000000-0000-0000-0000-000000000002",
            ),
            tools={},
        )
        with pytest.raises(ValidationError):
            cfg.client_name = "Changed"  # type: ignore[misc]


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
        bad_file.write_text(": : : not valid yaml [[[", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(bad_file)

    def test_load_non_mapping_tools_section_raises(self, tmp_path: Path) -> None:
        """Non-mapping optional sections (e.g., tools: [a, b]) raise ConfigError."""
        bad_file = tmp_path / "bad_section.yaml"
        bad_file.write_text(
            "client:\n  name: Test\n  tenant_id: t1\n"
            "auth:\n  method: client_credential\n  tenant_id: t1\n  client_id: c1\n"
            "tools:\n  - item1\n  - item2\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigError, match=r"tools.*mapping"):
            load_config(bad_file)

    def test_load_missing_client_section_raises(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "no_client.yaml"
        bad_file.write_text(
            "auth:\n  method: client_credential\n  tenant_id: t1\n  client_id: c1\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigError, match=r"Missing required.*client"):
            load_config(bad_file)

    def test_load_non_mapping_auth_section_raises(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad_auth.yaml"
        bad_file.write_text(
            "client:\n  name: Test\n  tenant_id: t1\nauth: just-a-string\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigError, match=r"auth.*mapping"):
            load_config(bad_file)

    def test_load_scalar_yaml_raises(self, tmp_path: Path) -> None:
        """True non-mapping YAML (scalar at root) raises ConfigError."""
        bad_file = tmp_path / "scalar.yaml"
        bad_file.write_text("just a string", encoding="utf-8")
        with pytest.raises(ConfigError, match="YAML mapping"):
            load_config(bad_file)

    def test_load_config_raises_validation_error_on_empty_client_name(self, tmp_path: Path) -> None:
        f = tmp_path / "empty_name.yaml"
        f.write_text(
            "client:\n  name: ''\n  tenant_id: t1\n"
            "auth:\n  method: client_credential\n  tenant_id: t1\n  client_id: c1\n"
            "tools:\n  scubagear: true\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigValidationError):
            load_config(f)

    def test_load_config_raises_validation_error_on_empty_auth_client_id(
        self, tmp_path: Path
    ) -> None:
        f = tmp_path / "empty_client_id.yaml"
        f.write_text(
            "client:\n  name: Test\n  tenant_id: t1\n"
            "auth:\n  method: client_credential\n  tenant_id: t1\n  client_id: ''\n"
            "tools:\n  scubagear: true\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigValidationError):
            load_config(f)

    def test_load_non_utf8_config_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "latin1.yaml"
        f.write_bytes(b"client:\n  name: \xe9\xe0\xfc\n")
        with pytest.raises(ConfigError, match="not valid UTF-8"):
            load_config(f)

    def test_load_yaml_null_section_raises(self, tmp_path: Path) -> None:
        """YAML null section (client: with no value -> None) raises ConfigError."""
        f = tmp_path / "null_section.yaml"
        f.write_text(
            "client:\nauth:\n  method: client_credential\n  tenant_id: t1\n  client_id: c1\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigError, match=r"client.*mapping.*NoneType"):
            load_config(f)

    def test_load_pydantic_type_coercion_failure_raises(self, tmp_path: Path) -> None:
        """Pydantic type coercion failure -> ConfigError."""
        f = tmp_path / "bad_type.yaml"
        f.write_text(
            "client:\n  name: Test\n  tenant_id: t1\n"
            "auth:\n  method: client_credential\n  tenant_id: t1\n  client_id: c1\n"
            "tools:\n  scubagear:\n    enabled: true\n    timeout: not_a_number\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigError):
            load_config(f)

    def test_load_tool_config_shorthand(self, tmp_path: Path) -> None:
        """Tool config shorthand: scubagear: true / maester: false."""
        f = tmp_path / "shorthand.yaml"
        f.write_text(
            "client:\n  name: Test\n  tenant_id: t1\n"
            "auth:\n  method: client_credential\n  tenant_id: t1\n  client_id: c1\n"
            "tools:\n  scubagear: true\n  maester: false\n",
            encoding="utf-8",
        )
        cfg = load_config(f)
        assert cfg.tools["scubagear"].enabled is True
        assert cfg.tools["maester"].enabled is False

    def test_load_tool_shorthand_string_raises(self, tmp_path: Path) -> None:
        """Quoted YAML string 'false' must not be silently coerced to True."""
        f = tmp_path / "string_tool.yaml"
        f.write_text(
            "client:\n  name: Test\n  tenant_id: t1\n"
            "auth:\n  method: client_credential\n  tenant_id: t1\n  client_id: c1\n"
            "tools:\n  scubagear: 'false'\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigError, match=r"scubagear.*boolean.*str"):
            load_config(f)


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

    def test_empty_client_name_is_error(self) -> None:
        cfg = EngagementConfig(
            client_name="",
            tenant_id="t1",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="t1",
                client_id="c1",
            ),
            tools={},
        )
        errors, _warnings = validate_config(cfg)
        assert any("client_name" in e for e in errors)

    def test_empty_auth_client_id_is_error(self) -> None:
        cfg = EngagementConfig(
            client_name="Test",
            tenant_id="t1",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="t1",
                client_id="",
            ),
            tools={},
        )
        errors, _warnings = validate_config(cfg)
        assert any("auth.client_id" in e for e in errors)

    def test_validate_collects_all_errors(self) -> None:
        """validate_config does not short-circuit -- all errors are collected."""
        cfg = EngagementConfig(
            client_name="",
            tenant_id="",
            auth=AuthConfig(
                method="client_credential",
                tenant_id="",
                client_id="",
            ),
            tools={},
        )
        errors, _warnings = validate_config(cfg)
        # Exactly 4: tenant_id, client_name, auth.tenant_id, auth.client_id
        assert len(errors) == 4
