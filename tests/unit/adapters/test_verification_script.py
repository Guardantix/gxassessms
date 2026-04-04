"""Tests for verification script builder and runner."""

from __future__ import annotations

import json

import pytest

from gxassessms.core.contracts.verification import (
    ModulePolicy,
    ModulePolicyOverride,
    SignerIdentity,
)


def _policy() -> ModulePolicy:
    return ModulePolicy(
        module_name="TestModule",
        version_range=">=1.0.0,<2.0.0",
        allowed_signers=frozenset({SignerIdentity(subject="CN=Good", issuer="CN=Root")}),
        approved_package_hashes=frozenset({"sha256tree:v1:" + "a" * 64}),
        allow_package_hash_fallback=True,
    )


class TestBuildInputBlob:
    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.adapters._verification import build_input_blob

        self.build_input_blob = build_input_blob

    def test_preflight_mode_no_invocation(self) -> None:
        blob = self.build_input_blob(
            policy=_policy(),
            override=None,
            mode="preflight",
            post_import_invocation=None,
        )
        data = json.loads(blob)
        assert data["module_name"] == "TestModule"
        assert data["mode"] == "preflight"
        assert data["post_import_invocation"] is None

    def test_collection_mode_with_invocation(self) -> None:
        invocation = {
            "command_name": "Invoke-SCuBA",
            "named_args": {"OutPath": "/out"},
            "switches": {},
        }
        blob = self.build_input_blob(
            policy=_policy(),
            override=None,
            mode="collection",
            post_import_invocation=invocation,
        )
        data = json.loads(blob)
        assert data["mode"] == "collection"
        assert data["post_import_invocation"]["command_name"] == "Invoke-SCuBA"

    def test_override_narrows_version(self) -> None:
        override = ModulePolicyOverride(version_range="==1.5.0")
        blob = self.build_input_blob(
            policy=_policy(),
            override=override,
            mode="preflight",
            post_import_invocation=None,
        )
        data = json.loads(blob)
        assert data["effective_version_range"] == "==1.5.0"

    def test_override_narrows_hashes(self) -> None:
        override = ModulePolicyOverride(
            pinned_package_hashes=frozenset({"sha256tree:v1:" + "a" * 64})
        )
        blob = self.build_input_blob(
            policy=_policy(),
            override=override,
            mode="preflight",
            post_import_invocation=None,
        )
        data = json.loads(blob)
        assert len(data["effective_approved_hashes"]) == 1

    def test_override_version_outside_range_rejected(self) -> None:
        override = ModulePolicyOverride(version_range="==3.0.0")
        with pytest.raises(ValueError, match="does not satisfy"):
            self.build_input_blob(
                policy=_policy(),
                override=override,
                mode="preflight",
                post_import_invocation=None,
            )

    def test_override_hashes_not_in_approved_set_rejected(self) -> None:
        override = ModulePolicyOverride(
            pinned_package_hashes=frozenset({"sha256tree:v1:" + "b" * 64})
        )
        with pytest.raises(ValueError, match=r"not in.*code-owned"):
            self.build_input_blob(
                policy=_policy(),
                override=override,
                mode="preflight",
                post_import_invocation=None,
            )


class TestValidateCommandAllowlist:
    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.adapters._verification import validate_command_allowlist

        self.validate_command_allowlist = validate_command_allowlist

    def test_allowed_command(self) -> None:
        self.validate_command_allowlist("Invoke-SCuBA", frozenset({"Invoke-SCuBA"}))

    def test_rejected_command_raises(self) -> None:
        with pytest.raises(ValueError, match=r"not in.*allowlist"):
            self.validate_command_allowlist("Invoke-Expression", frozenset({"Invoke-SCuBA"}))


class TestGetTemplatePath:
    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.adapters._verification import get_template_path

        self.get_template_path = get_template_path

    def test_template_path_exists(self) -> None:
        path = self.get_template_path()
        # Path should be absolute and end with .ps1
        assert path.suffix == ".ps1"
        assert path.name == "verify_module.ps1"
