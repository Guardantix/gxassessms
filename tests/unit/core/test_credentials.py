"""Tests for CredentialProvider Protocol and EnvVarProvider."""

import os
from typing import runtime_checkable

import pytest

from gxassessms.core.contracts.credentials import (
    CredentialProvider,
    EnvVarProvider,
)


class TestCredentialProviderProtocol:
    def test_protocol_is_runtime_checkable(self) -> None:
        assert runtime_checkable  # import check
        assert isinstance(EnvVarProvider(), CredentialProvider)


class TestEnvVarProvider:
    def test_get_credential_returns_env_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GX_TEST_SECRET", "s3cret")
        provider = EnvVarProvider()
        assert provider.get_credential("GX_TEST_SECRET") == "s3cret"

    def test_get_credential_raises_on_missing(self) -> None:
        provider = EnvVarProvider()
        # Use a key that definitely doesn't exist
        with pytest.raises(KeyError):
            provider.get_credential("GX_DEFINITELY_NOT_SET_12345")

    def test_has_credential_true_when_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GX_TEST_CHECK", "value")
        provider = EnvVarProvider()
        assert provider.has_credential("GX_TEST_CHECK") is True

    def test_has_credential_false_when_missing(self) -> None:
        provider = EnvVarProvider()
        assert provider.has_credential("GX_DEFINITELY_NOT_SET_12345") is False

    def test_get_credential_strips_whitespace(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GX_TEST_STRIP", "  value  ")
        provider = EnvVarProvider()
        # Should return raw value -- no stripping (secrets may have spaces)
        assert provider.get_credential("GX_TEST_STRIP") == "  value  "
