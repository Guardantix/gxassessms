"""Unit tests for the shared Azure token acquisition helper."""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest

from gxassessms.core.contracts.errors import CollectionError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SCOPE = "https://management.azure.com/.default"
_ADAPTER = "TestAdapter"


def _mock_azure_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[MagicMock, MagicMock, MagicMock, MagicMock]:
    """Inject mock azure.identity and azure.core.exceptions into sys.modules.

    Returns (ClientSecretCredential, CertificateCredential,
             DeviceCodeCredential, InteractiveBrowserCredential) constructor mocks.
    """
    fake_token = SimpleNamespace(token="tok", expires_on=9_999_999_999)

    sp_cred = MagicMock()
    sp_cred.get_token.return_value = fake_token
    ClientSecretCredential = MagicMock(return_value=sp_cred)

    cert_cred = MagicMock()
    cert_cred.get_token.return_value = fake_token
    CertificateCredential = MagicMock(return_value=cert_cred)

    dc_cred = MagicMock()
    dc_cred.get_token.return_value = fake_token
    DeviceCodeCredential = MagicMock(return_value=dc_cred)

    ib_cred = MagicMock()
    ib_cred.get_token.return_value = fake_token
    InteractiveBrowserCredential = MagicMock(return_value=ib_cred)

    mock_identity = ModuleType("azure.identity")
    mock_identity.ClientSecretCredential = ClientSecretCredential  # type: ignore[attr-defined]
    mock_identity.CertificateCredential = CertificateCredential  # type: ignore[attr-defined]
    mock_identity.DeviceCodeCredential = DeviceCodeCredential  # type: ignore[attr-defined]
    mock_identity.InteractiveBrowserCredential = InteractiveBrowserCredential  # type: ignore[attr-defined]

    mock_azure_core = ModuleType("azure.core.exceptions")
    mock_azure_core.AzureError = Exception  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "azure.identity", mock_identity)
    monkeypatch.setitem(sys.modules, "azure.core.exceptions", mock_azure_core)

    return (
        ClientSecretCredential,
        CertificateCredential,
        DeviceCodeCredential,
        InteractiveBrowserCredential,
    )


def _auth_config(
    *,
    method: str = "client_credential",
    client_secret_env: str = "",
    certificate_path: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        auth=SimpleNamespace(
            method=method,
            client_id="app-id",
            client_secret_env=client_secret_env,
            certificate_path=certificate_path,
            tenant_id="tenant-id",
        )
    )


# ---------------------------------------------------------------------------
# Error path tests
# ---------------------------------------------------------------------------


class TestErrorPaths:
    def test_import_error_raises_collection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ImportError from missing azure-identity becomes CollectionError."""
        monkeypatch.setitem(sys.modules, "azure.core.exceptions", None)
        from gxassessms.adapters._azure_auth import acquire_azure_token

        with pytest.raises(CollectionError, match="azure-identity is required"):
            acquire_azure_token(
                _auth_config(),  # type: ignore[arg-type]
                scope=_SCOPE,
                adapter_name=_ADAPTER,
            )

    def test_env_var_not_set_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """client_secret_env naming a non-existent env var raises CollectionError."""
        _mock_azure_identity(monkeypatch)
        monkeypatch.delenv("GX_MISSING_SECRET", raising=False)
        from gxassessms.adapters._azure_auth import acquire_azure_token

        with pytest.raises(CollectionError, match="not set or empty"):
            acquire_azure_token(
                _auth_config(client_secret_env="GX_MISSING_SECRET"),  # type: ignore[arg-type]  # pragma: allowlist secret
                scope=_SCOPE,
                adapter_name=_ADAPTER,
            )

    def test_env_var_set_but_empty_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """client_secret_env naming an env var set to '' raises CollectionError."""
        _mock_azure_identity(monkeypatch)
        monkeypatch.setenv("GX_EMPTY_SECRET", "")
        from gxassessms.adapters._azure_auth import acquire_azure_token

        with pytest.raises(CollectionError, match="not set or empty"):
            acquire_azure_token(
                _auth_config(client_secret_env="GX_EMPTY_SECRET"),  # type: ignore[arg-type]  # pragma: allowlist secret
                scope=_SCOPE,
                adapter_name=_ADAPTER,
            )

    def test_no_secret_or_cert_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """client_credential with neither secret nor cert raises CollectionError."""
        _mock_azure_identity(monkeypatch)
        from gxassessms.adapters._azure_auth import acquire_azure_token

        with pytest.raises(CollectionError, match="client_credential auth requires"):
            acquire_azure_token(
                _auth_config(method="client_credential"),  # type: ignore[arg-type]
                scope=_SCOPE,
                adapter_name=_ADAPTER,
            )

    def test_unsupported_method_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unknown auth method raises CollectionError."""
        _mock_azure_identity(monkeypatch)
        from gxassessms.adapters._azure_auth import acquire_azure_token

        with pytest.raises(CollectionError, match="Unsupported auth method"):
            acquire_azure_token(
                _auth_config(method="bogus"),  # type: ignore[arg-type]
                scope=_SCOPE,
                adapter_name=_ADAPTER,
            )

    def test_azure_error_wraps_as_collection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """AzureError from get_token() wraps as CollectionError."""
        ClientSecretCredential, _, _, _ = _mock_azure_identity(monkeypatch)
        cred_instance = ClientSecretCredential.return_value
        cred_instance.get_token.side_effect = Exception("auth failure")
        monkeypatch.setenv("GX_TEST_SECRET", "s3cr3t")
        from gxassessms.adapters._azure_auth import acquire_azure_token

        with pytest.raises(CollectionError, match="Azure token acquisition failed"):
            acquire_azure_token(
                _auth_config(client_secret_env="GX_TEST_SECRET"),  # type: ignore[arg-type]  # pragma: allowlist secret
                scope=_SCOPE,
                adapter_name=_ADAPTER,
            )

    def test_value_error_wraps_as_collection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ValueError from credential construction wraps as CollectionError."""
        ClientSecretCredential, _, _, _ = _mock_azure_identity(monkeypatch)
        ClientSecretCredential.side_effect = ValueError("bad tenant")
        monkeypatch.setenv("GX_TEST_SECRET", "s3cr3t")
        from gxassessms.adapters._azure_auth import acquire_azure_token

        with pytest.raises(CollectionError, match="Azure token acquisition failed"):
            acquire_azure_token(
                _auth_config(client_secret_env="GX_TEST_SECRET"),  # type: ignore[arg-type]  # pragma: allowlist secret
                scope=_SCOPE,
                adapter_name=_ADAPTER,
            )


# ---------------------------------------------------------------------------
# Happy path tests
# ---------------------------------------------------------------------------


class TestHappyPaths:
    def test_client_secret_credential_happy_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """client_credential + client_secret_env returns full AuthContext."""
        ClientSecretCredential, _, _, _ = _mock_azure_identity(monkeypatch)
        monkeypatch.setenv("GX_TEST_SECRET", "s3cr3t")
        from gxassessms.adapters._azure_auth import acquire_azure_token

        result = acquire_azure_token(
            _auth_config(client_secret_env="GX_TEST_SECRET"),  # type: ignore[arg-type]  # pragma: allowlist secret
            scope=_SCOPE,
            adapter_name=_ADAPTER,
        )
        assert result.token.get_secret_value() == "tok"
        assert result.extra == {"scope": _SCOPE}
        assert result.expires_at is not None
        ClientSecretCredential.assert_called_once_with(
            tenant_id="tenant-id",
            client_id="app-id",
            client_secret="s3cr3t",  # pragma: allowlist secret
        )

    def test_certificate_credential_happy_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """client_credential + certificate_path returns full AuthContext."""
        _, CertificateCredential, _, _ = _mock_azure_identity(monkeypatch)
        from gxassessms.adapters._azure_auth import acquire_azure_token

        result = acquire_azure_token(
            _auth_config(certificate_path="/path/to/cert.pem"),  # type: ignore[arg-type]
            scope=_SCOPE,
            adapter_name=_ADAPTER,
        )
        assert result.token.get_secret_value() == "tok"
        assert result.extra == {"scope": _SCOPE}
        assert result.expires_at is not None
        CertificateCredential.assert_called_once_with(
            tenant_id="tenant-id",
            client_id="app-id",
            certificate_path="/path/to/cert.pem",
        )

    def test_device_code_credential_happy_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """device_code method returns full AuthContext."""
        _, _, DeviceCodeCredential, _ = _mock_azure_identity(monkeypatch)
        from gxassessms.adapters._azure_auth import acquire_azure_token

        result = acquire_azure_token(
            _auth_config(method="device_code"),  # type: ignore[arg-type]
            scope=_SCOPE,
            adapter_name=_ADAPTER,
        )
        assert result.token.get_secret_value() == "tok"
        assert result.extra == {"scope": _SCOPE}
        assert result.expires_at is not None
        DeviceCodeCredential.assert_called_once_with(
            client_id="app-id",
            tenant_id="tenant-id",
        )

    def test_interactive_browser_credential_happy_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """interactive method returns full AuthContext."""
        _, _, _, InteractiveBrowserCredential = _mock_azure_identity(monkeypatch)
        from gxassessms.adapters._azure_auth import acquire_azure_token

        result = acquire_azure_token(
            _auth_config(method="interactive"),  # type: ignore[arg-type]
            scope=_SCOPE,
            adapter_name=_ADAPTER,
        )
        assert result.token.get_secret_value() == "tok"
        assert result.extra == {"scope": _SCOPE}
        assert result.expires_at is not None
        InteractiveBrowserCredential.assert_called_once_with(
            tenant_id="tenant-id",
            client_id="app-id",
        )


# ---------------------------------------------------------------------------
# Precedence / dispatch tests
# ---------------------------------------------------------------------------


class TestDispatchPrecedence:
    def test_client_secret_takes_precedence_over_certificate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When both client_secret_env and certificate_path are set, secret wins."""
        ClientSecretCredential, CertificateCredential, _, _ = _mock_azure_identity(monkeypatch)
        monkeypatch.setenv("GX_TEST_SECRET", "s3cr3t")
        from gxassessms.adapters._azure_auth import acquire_azure_token

        result = acquire_azure_token(
            _auth_config(
                client_secret_env="GX_TEST_SECRET",  # pragma: allowlist secret
                certificate_path="/path/to/cert.pem",
            ),  # type: ignore[arg-type]
            scope=_SCOPE,
            adapter_name=_ADAPTER,
        )
        assert result is not None
        ClientSecretCredential.assert_called_once()
        CertificateCredential.assert_not_called()

    def test_device_code_ignores_leftover_client_secret_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """method='device_code' with leftover client_secret_env uses DeviceCodeCredential."""
        ClientSecretCredential, _, DeviceCodeCredential, _ = _mock_azure_identity(monkeypatch)
        monkeypatch.setenv("GX_TEST_SECRET", "s3cr3t")
        from gxassessms.adapters._azure_auth import acquire_azure_token

        result = acquire_azure_token(
            _auth_config(
                method="device_code",
                client_secret_env="GX_TEST_SECRET",  # pragma: allowlist secret
            ),  # type: ignore[arg-type]
            scope=_SCOPE,
            adapter_name=_ADAPTER,
        )
        assert result is not None
        DeviceCodeCredential.assert_called_once()
        ClientSecretCredential.assert_not_called()

    def test_interactive_ignores_leftover_certificate_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """method='interactive' with leftover certificate_path uses InteractiveBrowserCredential."""
        _, CertificateCredential, _, InteractiveBrowserCredential = _mock_azure_identity(
            monkeypatch
        )
        from gxassessms.adapters._azure_auth import acquire_azure_token

        result = acquire_azure_token(
            _auth_config(
                method="interactive",
                certificate_path="/path/to/cert.pem",
            ),  # type: ignore[arg-type]
            scope=_SCOPE,
            adapter_name=_ADAPTER,
        )
        assert result is not None
        InteractiveBrowserCredential.assert_called_once()
        CertificateCredential.assert_not_called()


# ---------------------------------------------------------------------------
# Integration assertion tests
# ---------------------------------------------------------------------------


class TestIntegrationAssertions:
    def test_scope_passed_to_get_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The scope parameter reaches credential.get_token(scope)."""
        _, _, DeviceCodeCredential, _ = _mock_azure_identity(monkeypatch)
        cred_instance = DeviceCodeCredential.return_value
        from gxassessms.adapters._azure_auth import acquire_azure_token

        custom_scope = "https://graph.microsoft.com/.default"
        acquire_azure_token(
            _auth_config(method="device_code"),  # type: ignore[arg-type]
            scope=custom_scope,
            adapter_name=_ADAPTER,
        )
        cred_instance.get_token.assert_called_once_with(custom_scope)

    def test_adapter_name_in_collection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """adapter_name propagates into CollectionError."""
        _mock_azure_identity(monkeypatch)
        from gxassessms.adapters._azure_auth import acquire_azure_token

        with pytest.raises(CollectionError) as exc_info:
            acquire_azure_token(
                _auth_config(method="bogus"),  # type: ignore[arg-type]
                scope=_SCOPE,
                adapter_name="MyCustomAdapter",
            )
        assert exc_info.value.adapter_name == "MyCustomAdapter"

    def test_auth_context_contains_scope_in_extra(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """AuthContext.extra contains the scope that was requested."""
        _mock_azure_identity(monkeypatch)
        from gxassessms.adapters._azure_auth import acquire_azure_token

        custom_scope = "https://vault.azure.net/.default"
        result = acquire_azure_token(
            _auth_config(method="device_code"),  # type: ignore[arg-type]
            scope=custom_scope,
            adapter_name=_ADAPTER,
        )
        assert result.extra == {"scope": custom_scope}
