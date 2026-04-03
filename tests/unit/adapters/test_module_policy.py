"""Tests for ModulePolicy construction invariants and ModulePolicyOverride validation."""

from __future__ import annotations

import pytest


class TestSignerIdentity:
    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.core.contracts.verification import SignerIdentity

        self.SignerIdentity = SignerIdentity

    def test_construction(self) -> None:
        si = self.SignerIdentity(subject="CN=Test", issuer="CN=Root")
        assert si.subject == "CN=Test"
        assert si.issuer == "CN=Root"

    def test_frozen(self) -> None:
        si = self.SignerIdentity(subject="CN=Test", issuer="CN=Root")
        with pytest.raises(AttributeError):
            si.subject = "CN=Other"  # type: ignore[misc]

    def test_equality(self) -> None:
        a = self.SignerIdentity(subject="CN=Test", issuer="CN=Root")
        b = self.SignerIdentity(subject="CN=Test", issuer="CN=Root")
        assert a == b

    def test_hashable(self) -> None:
        si = self.SignerIdentity(subject="CN=Test", issuer="CN=Root")
        assert {si}  # Can be in a frozenset


class TestModulePolicy:
    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.core.contracts.verification import (
            ModulePolicy,
            SignerIdentity,
        )

        self.ModulePolicy = ModulePolicy
        self.SignerIdentity = SignerIdentity

    def _signer(self) -> frozenset:
        return frozenset({self.SignerIdentity(subject="CN=Test", issuer="CN=Root")})

    def _hashes(self) -> frozenset:
        return frozenset({"sha256tree:v1:" + "a" * 64})

    def test_valid_construction(self) -> None:
        p = self.ModulePolicy(
            module_name="ScubaGear",
            version_range=">=1.5.0,<2.0.0",
            allowed_signers=self._signer(),
            approved_package_hashes=self._hashes(),
            allow_package_hash_fallback=True,
        )
        assert p.module_name == "ScubaGear"

    def test_empty_signers_rejected(self) -> None:
        with pytest.raises(ValueError, match="allowed_signers"):
            self.ModulePolicy(
                module_name="ScubaGear",
                version_range=">=1.0.0",
                allowed_signers=frozenset(),
                approved_package_hashes=self._hashes(),
                allow_package_hash_fallback=True,
            )

    def test_empty_hashes_rejected(self) -> None:
        with pytest.raises(ValueError, match="approved_package_hashes"):
            self.ModulePolicy(
                module_name="ScubaGear",
                version_range=">=1.0.0",
                allowed_signers=self._signer(),
                approved_package_hashes=frozenset(),
                allow_package_hash_fallback=True,
            )

    def test_hash_missing_prefix_rejected(self) -> None:
        with pytest.raises(ValueError, match="sha256tree:v1:"):
            self.ModulePolicy(
                module_name="ScubaGear",
                version_range=">=1.0.0",
                allowed_signers=self._signer(),
                approved_package_hashes=frozenset({"badhash"}),
                allow_package_hash_fallback=True,
            )

    def test_invalid_version_range_rejected(self) -> None:
        with pytest.raises(ValueError, match="version_range"):
            self.ModulePolicy(
                module_name="ScubaGear",
                version_range="not-a-range",
                allowed_signers=self._signer(),
                approved_package_hashes=self._hashes(),
                allow_package_hash_fallback=True,
            )

    def test_frozen(self) -> None:
        p = self.ModulePolicy(
            module_name="ScubaGear",
            version_range=">=1.0.0",
            allowed_signers=self._signer(),
            approved_package_hashes=self._hashes(),
            allow_package_hash_fallback=True,
        )
        with pytest.raises(AttributeError):
            p.module_name = "Other"  # type: ignore[misc]


class TestModulePolicyOverride:
    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.core.contracts.verification import (
            ModulePolicy,
            ModulePolicyOverride,
            SignerIdentity,
        )

        self.ModulePolicy = ModulePolicy
        self.ModulePolicyOverride = ModulePolicyOverride
        self.SignerIdentity = SignerIdentity

    def _base_policy(self) -> object:
        return self.ModulePolicy(
            module_name="ScubaGear",
            version_range=">=1.5.0,<2.0.0",
            allowed_signers=frozenset({self.SignerIdentity(subject="CN=Test", issuer="CN=Root")}),
            approved_package_hashes=frozenset({"sha256tree:v1:" + "a" * 64}),
            allow_package_hash_fallback=True,
        )

    def test_exact_pin_within_range(self) -> None:
        override = self.ModulePolicyOverride(version_range="==1.5.2")
        assert override.version_range == "==1.5.2"

    def test_non_exact_pin_rejected(self) -> None:
        with pytest.raises(ValueError, match="exact-version pin"):
            self.ModulePolicyOverride(version_range=">=1.5.0")

    def test_pinned_hashes_valid(self) -> None:
        override = self.ModulePolicyOverride(
            pinned_package_hashes=frozenset({"sha256tree:v1:" + "a" * 64})
        )
        assert override.pinned_package_hashes is not None

    def test_empty_pinned_hashes_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            self.ModulePolicyOverride(pinned_package_hashes=frozenset())

    def test_none_fields_are_default(self) -> None:
        override = self.ModulePolicyOverride()
        assert override.version_range is None
        assert override.pinned_package_hashes is None
