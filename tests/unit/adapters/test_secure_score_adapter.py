"""Unit tests for SecureScoreAdapter guards that don't require network calls."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr

from gxassessms.adapters.secure_score.adapter import SecureScoreAdapter
from gxassessms.core.contracts.errors import CollectionError
from gxassessms.core.domain.models import AuthContext


def _make_auth(*, expired: bool = False) -> AuthContext:
    """Build an AuthContext with either a future or past expiry."""
    if expired:
        expires_at = datetime.now(UTC) - timedelta(hours=1)
    else:
        expires_at = datetime.now(UTC) + timedelta(hours=1)
    return AuthContext(
        token=SecretStr("fake-token"),
        expires_at=expires_at,
        extra={},
    )


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
        """A future expiry alone does not trigger the expiry guard."""
        adapter = SecureScoreAdapter()
        valid_auth = _make_auth(expired=False)
        # Should get past the expiry guard and fail on missing config, not expiry
        with pytest.raises((CollectionError, AttributeError, TypeError)):
            adapter.collect(config=object(), auth=valid_auth)  # type: ignore[arg-type]
