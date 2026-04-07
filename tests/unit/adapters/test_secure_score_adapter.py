"""Unit tests for SecureScoreAdapter guards that don't require network calls."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

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


class TestAuthenticate:
    def test_delegates_to_acquire_azure_token(self) -> None:
        """authenticate() delegates to shared acquire_azure_token with correct args."""
        adapter = SecureScoreAdapter()
        config = SimpleNamespace()  # opaque; passed through to mock
        sentinel = AuthContext(
            token=SecretStr("test-token"),  # pragma: allowlist secret
            extra={"scope": "https://graph.microsoft.com/.default"},
            expires_at=utc_now(),
        )
        with patch(
            "gxassessms.adapters.secure_score.adapter.acquire_azure_token",
            return_value=sentinel,
        ) as mock_acquire:
            result = adapter.authenticate(config)  # type: ignore[arg-type]
        mock_acquire.assert_called_once_with(
            config,
            scope="https://graph.microsoft.com/.default",
            adapter_name="SecureScore",
        )
        assert result is sentinel

    def test_propagates_collection_error(self) -> None:
        """CollectionError from acquire_azure_token propagates unchanged."""
        adapter = SecureScoreAdapter()
        with (
            patch(
                "gxassessms.adapters.secure_score.adapter.acquire_azure_token",
                side_effect=CollectionError("boom", adapter_name="SecureScore"),
            ),
            pytest.raises(CollectionError, match="boom"),
        ):
            adapter.authenticate(SimpleNamespace())  # type: ignore[arg-type]


class TestCollectGuards:
    def test_raises_if_auth_is_none(self) -> None:
        """collect() raises CollectionError when auth is None."""
        adapter = SecureScoreAdapter()
        with pytest.raises(CollectionError, match="no auth context provided"):
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
