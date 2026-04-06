"""Unit tests for SecureScoreAdapter guards that don't require network calls."""

import sys
from datetime import timedelta
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from gxassessms.adapters.secure_score.adapter import SecureScoreAdapter
from gxassessms.core.config.datetime_utils import utc_now
from gxassessms.core.contracts.errors import CollectionError
from gxassessms.core.domain.models import AuthContext


def _make_auth(*, expired: bool = False) -> AuthContext:
    """Build an AuthContext with either a future or past expiry."""
    expires_at = utc_now() - timedelta(hours=1) if expired else utc_now() + timedelta(hours=1)
    return AuthContext(
        token=SecretStr("fake-token"),
        expires_at=expires_at,
        extra={},
    )


def _stub_config() -> SimpleNamespace:
    """Minimal config stub that passes auth checks but has no output_dir."""
    tc = SimpleNamespace(output_dir=None, timeout=None)
    return SimpleNamespace(tools={"securescore": tc})


class TestAdapterProperties:
    def test_severity_map_covers_all_domain_severities_for_fail(self) -> None:
        """severity_map passes through all domain severities for FAIL status."""
        adapter = SecureScoreAdapter()
        smap = adapter.severity_map
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert smap.get((sev, "FAIL")) == sev, (
                f"severity_map missing or wrong for ({sev!r}, 'FAIL')"
            )

    def test_severity_map_covers_all_domain_severities_for_manual(self) -> None:
        """severity_map passes through all domain severities for MANUAL status."""
        adapter = SecureScoreAdapter()
        smap = adapter.severity_map
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert smap.get((sev, "MANUAL")) == sev

    def test_tool_name_lower_matches_config_key_convention(self) -> None:
        """tool_name.lower() matches the key used by collect() for config lookup.

        All other adapters (ScubaGear, Maester) use self.tool_name.lower() as the
        config key. This test guards against a regression to a hardcoded mismatch.
        """
        adapter = SecureScoreAdapter()
        # tool_name = "SecureScore", tool_name.lower() = "securescore"
        assert adapter.tool_name.lower() == "securescore"


def _mock_azure_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[MagicMock, MagicMock, MagicMock]:
    """Inject mock azure.identity and azure.core.exceptions into sys.modules.

    Returns (ClientSecretCredential mock, DefaultAzureCredential mock,
             CertificateCredential mock).
    """
    fake_token = SimpleNamespace(token="tok", expires_on=9_999_999_999)

    sp_cred = MagicMock()
    sp_cred.get_token.return_value = fake_token
    ClientSecretCredential = MagicMock(return_value=sp_cred)

    dac_cred = MagicMock()
    dac_cred.get_token.return_value = fake_token
    DefaultAzureCredential = MagicMock(return_value=dac_cred)

    cert_cred = MagicMock()
    cert_cred.get_token.return_value = fake_token
    CertificateCredential = MagicMock(return_value=cert_cred)

    mock_identity = ModuleType("azure.identity")
    mock_identity.ClientSecretCredential = ClientSecretCredential  # type: ignore[attr-defined]
    mock_identity.DefaultAzureCredential = DefaultAzureCredential  # type: ignore[attr-defined]
    mock_identity.CertificateCredential = CertificateCredential  # type: ignore[attr-defined]

    mock_azure_core = ModuleType("azure.core.exceptions")
    mock_azure_core.AzureError = Exception  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "azure.identity", mock_identity)
    monkeypatch.setitem(sys.modules, "azure.core.exceptions", mock_azure_core)

    return ClientSecretCredential, DefaultAzureCredential, CertificateCredential


def _auth_config(
    *, client_secret_env: str = "", certificate_path: str | None = None
) -> SimpleNamespace:
    return SimpleNamespace(
        auth=SimpleNamespace(
            client_id="app-id",
            client_secret_env=client_secret_env,
            certificate_path=certificate_path,
            tenant_id="tenant-id",
        )
    )


class TestAuthenticate:
    def test_uses_default_credential_when_no_secret_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """authenticate() uses DefaultAzureCredential when client_secret_env is empty.

        Regression: auth config requires client_id (always set), so the old
        ``elif client_id and not client_secret_env`` guard always fired for
        non-SP users, blocking DefaultAzureCredential entirely.
        """
        _, DefaultAzureCredential, _ = _mock_azure_identity(monkeypatch)
        adapter = SecureScoreAdapter()
        result = adapter.authenticate(_auth_config(client_secret_env=""))  # type: ignore[arg-type]
        assert result is not None
        DefaultAzureCredential.assert_called_once()

    def test_uses_client_secret_credential_when_secret_env_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """authenticate() uses ClientSecretCredential when client_secret_env is set."""
        ClientSecretCredential, DefaultAzureCredential, _ = _mock_azure_identity(monkeypatch)
        monkeypatch.setenv("GX_TEST_SECRET", "s3cr3t")
        adapter = SecureScoreAdapter()
        result = adapter.authenticate(  # type: ignore[arg-type]
            _auth_config(client_secret_env="GX_TEST_SECRET")  # pragma: allowlist secret
        )
        assert result is not None
        ClientSecretCredential.assert_called_once()
        DefaultAzureCredential.assert_not_called()

    def test_raises_if_secret_env_set_but_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """authenticate() raises CollectionError when secret env var is set but empty."""
        _mock_azure_identity(monkeypatch)
        monkeypatch.delenv("GX_MISSING_SECRET", raising=False)
        adapter = SecureScoreAdapter()
        with pytest.raises(CollectionError, match="not set or empty"):
            adapter.authenticate(  # type: ignore[arg-type]
                _auth_config(client_secret_env="GX_MISSING_SECRET")  # pragma: allowlist secret
            )

    def test_uses_certificate_credential_when_certificate_path_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """authenticate() uses CertificateCredential when certificate_path is set."""
        _, DefaultAzureCredential, CertificateCredential = _mock_azure_identity(monkeypatch)
        adapter = SecureScoreAdapter()
        result = adapter.authenticate(  # type: ignore[arg-type]
            _auth_config(certificate_path="/path/to/cert.pem")
        )
        assert result is not None
        CertificateCredential.assert_called_once()
        DefaultAzureCredential.assert_not_called()

    def test_client_secret_takes_precedence_over_certificate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """client_secret_env is preferred when both secret and certificate are configured."""
        ClientSecretCredential, _, CertificateCredential = _mock_azure_identity(monkeypatch)
        monkeypatch.setenv("GX_TEST_SECRET", "s3cr3t")
        adapter = SecureScoreAdapter()
        result = adapter.authenticate(  # type: ignore[arg-type]
            _auth_config(
                client_secret_env="GX_TEST_SECRET",  # pragma: allowlist secret
                certificate_path="/path/to/cert.pem",
            )
        )
        assert result is not None
        ClientSecretCredential.assert_called_once()
        CertificateCredential.assert_not_called()


class TestFetchGraphEndpointPagination:
    """Tests for _fetch_graph_endpoint max_pages behavior."""

    def test_max_pages_stops_after_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """max_pages=1 stops pagination after the first page, ignoring nextLink."""
        import httpx

        page1 = {
            "value": [{"id": "first"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/next-page",
        }

        mock_response = MagicMock()
        mock_response.json.return_value = page1
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        monkeypatch.setattr(httpx, "Client", MagicMock(return_value=mock_client))

        adapter = SecureScoreAdapter()
        result = adapter._fetch_graph_endpoint(
            "https://graph.microsoft.com/v1.0/security/secureScores?$top=1",
            headers={"Authorization": "Bearer fake"},
            timeout=30,
            label="secureScores",
            max_pages=1,
        )

        assert result == {"value": [{"id": "first"}]}
        mock_client.get.assert_called_once()

    def test_default_max_pages_uses_global_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without max_pages, pagination cap falls back to _MAX_PAGES."""
        import httpx

        from gxassessms.adapters.secure_score.adapter import _MAX_PAGES

        call_count = 0

        def mock_get(url: str, headers: dict[str, str]) -> MagicMock:  # type: ignore[type-arg]
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.json.return_value = {
                "value": [{"id": f"item-{call_count}"}],
                "@odata.nextLink": f"https://graph.microsoft.com/v1.0/next?page={call_count + 1}",
            }
            return resp

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get = mock_get
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        monkeypatch.setattr(httpx, "Client", MagicMock(return_value=mock_client))

        adapter = SecureScoreAdapter()
        with pytest.raises(CollectionError, match=f"exceeded {_MAX_PAGES} pages"):
            adapter._fetch_graph_endpoint(
                "https://graph.microsoft.com/v1.0/security/test",
                headers={"Authorization": "Bearer fake"},
                timeout=30,
                label="test",
            )

        assert call_count == _MAX_PAGES


class TestCollectGuards:
    def test_raises_if_auth_is_none(self) -> None:
        """collect() raises CollectionError when auth is None."""
        adapter = SecureScoreAdapter()
        with pytest.raises(CollectionError, match="requires authentication"):
            adapter.collect(config=object(), auth=None)  # type: ignore[arg-type]

    def test_raises_if_token_expired(self) -> None:
        """collect() raises CollectionError when the token has already expired."""
        adapter = SecureScoreAdapter()
        expired_auth = _make_auth(expired=True)
        with pytest.raises(CollectionError, match="expired"):
            adapter.collect(config=object(), auth=expired_auth)  # type: ignore[arg-type]

    def test_does_not_raise_for_valid_token_expiry(self) -> None:
        """A future expiry alone does not trigger the expiry guard.

        The test confirms execution reaches the config validation guard
        (which comes after the expiry guard), not the expiry guard itself.
        """
        adapter = SecureScoreAdapter()
        valid_auth = _make_auth(expired=False)
        # Must get past expiry guard and fail on missing output_dir, not expiry
        with pytest.raises(CollectionError, match="output_dir"):
            adapter.collect(config=_stub_config(), auth=valid_auth)  # type: ignore[arg-type]
